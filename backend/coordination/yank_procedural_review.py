"""Bounded procedural review for YANK arbitration outcomes.

Backend policy service only: one non-initiator challenge, one independent
procedural review, and at most one rerun of the original arbitration after a
substantiated defect. This service never releases output or grants authority.

Actor IDs must come from authenticated server-side principals. Participant,
reviewer, and Gate/rerun authorization are injected checks. State and signed
SCAR receipts are stored in file-backed SQLite. The existing SCARLedger may
still be process-memory-only; this module does not claim ledger durability.
"""
from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
from threading import RLock
from typing import Any, Callable, Iterator, Mapping, Sequence

DEFECT_CATEGORIES = frozenset({"OMITTED_EVIDENCE", "MISAPPLIED_CRITERIA", "CONFLICT_OF_INTEREST"})
REVIEW_FINDINGS = frozenset({"SUBSTANTIATED", "NOT_SUBSTANTIATED"})
RERUN_ACTIONS = frozenset({"PASS", "REWRITE", "YANK", "UNAVAILABLE"})
SHA3_512_RE = re.compile(r"^sha3-512:[0-9a-f]{128}$")


class YANKReviewError(RuntimeError):
    """Base error for rejected procedural-review operations."""


class YANKReviewDenied(PermissionError, YANKReviewError):
    """Identity, policy, or state-transition check rejected the operation."""


class YANKReviewConflict(YANKReviewError):
    """Operation conflicts with the bounded review/rerun limits."""


class YANKEvidenceError(YANKReviewError):
    """Required SCAR evidence could not be appended and acknowledged."""


class YANKReviewStoreError(YANKReviewError):
    """Persistent review-state storage is unavailable or invalid."""


ParticipantCheck = Callable[[str, str], bool]
ReviewerCheck = Callable[[str, str, str, tuple[str, ...]], bool]
RerunAuthorizer = Callable[[str, str, str], bool]
EvidenceSink = Callable[[dict[str, Any]], Any]
RerunHandler = Callable[[Mapping[str, Any]], Mapping[str, Any]]


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _required_text(value: Any, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be text")
    value = value.strip()
    if not value or len(value) > maximum:
        raise ValueError(f"{field} must contain 1..{maximum} characters")
    return value


def _evidence_refs(values: Sequence[str]) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence) or not 1 <= len(values) <= 20:
        raise ValueError("one to twenty evidence references are required")
    refs = tuple(_required_text(item, "evidence reference", 256) for item in values)
    if len(set(refs)) != len(refs):
        raise ValueError("duplicate evidence references are not permitted")
    return refs


def _decode(value: str) -> Any:
    return json.loads(value)


class YANKProceduralReviewService:
    """File-backed, fail-closed state machine for a bounded YANK appeal."""

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        *,
        evidence_sink: EvidenceSink,
        participant_check: ParticipantCheck,
        reviewer_check: ReviewerCheck,
        rerun_authorizer: RerunAuthorizer,
    ) -> None:
        raw_path = os.fspath(db_path)
        if not raw_path or raw_path == ":memory:":
            raise ValueError("a file-backed review database path is required")
        if not all(callable(x) for x in (evidence_sink, participant_check, reviewer_check, rerun_authorizer)):
            raise TypeError("SCAR sink, participant/reviewer checks, and Gate rerun authorization are mandatory")
        self.db_path = Path(raw_path).expanduser().resolve()
        self.db_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._evidence_sink = evidence_sink
        self._participant_check = participant_check
        self._reviewer_check = reviewer_check
        self._rerun_authorizer = rerun_authorizer
        self._lock = RLock()
        try:
            self._db = sqlite3.connect(str(self.db_path), timeout=10, isolation_level=None, check_same_thread=False)
            self._db.row_factory = sqlite3.Row
            self._db.execute("PRAGMA foreign_keys=ON")
            self._db.execute("PRAGMA busy_timeout=10000")
            self._db.execute("PRAGMA journal_mode=WAL")
            self._db.execute("PRAGMA synchronous=FULL")
            try:
                os.chmod(self.db_path, 0o600)
            except OSError:
                pass
            self._initialize_schema()
        except Exception as exc:
            raise YANKReviewStoreError("could not initialize persistent YANK review store") from exc

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def __enter__(self) -> "YANKProceduralReviewService":
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()

    def _initialize_schema(self) -> None:
        self._db.executescript("""
        CREATE TABLE IF NOT EXISTS yank_arbitrations (
          arbitration_id TEXT PRIMARY KEY, task_id TEXT NOT NULL, initiator_ids_json TEXT NOT NULL,
          candidate_hash TEXT NOT NULL, original_action TEXT NOT NULL CHECK(original_action='YANK'),
          state TEXT NOT NULL CHECK(state IN ('ESCROWED','CHALLENGE_FILED','READY_FOR_RERUN',
            'RERUN_IN_PROGRESS','RESOLVED','HELD_FOR_HUMAN_ESCALATION')),
          challenge_count INTEGER NOT NULL DEFAULT 0 CHECK(challenge_count BETWEEN 0 AND 1),
          review_count INTEGER NOT NULL DEFAULT 0 CHECK(review_count BETWEEN 0 AND 1),
          rerun_count INTEGER NOT NULL DEFAULT 0 CHECK(rerun_count BETWEEN 0 AND 1),
          created_at TEXT NOT NULL, updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS yank_challenges (
          arbitration_id TEXT PRIMARY KEY REFERENCES yank_arbitrations(arbitration_id),
          challenger_id TEXT NOT NULL,
          defect_category TEXT NOT NULL CHECK(defect_category IN ('OMITTED_EVIDENCE','MISAPPLIED_CRITERIA','CONFLICT_OF_INTEREST')),
          description TEXT NOT NULL, evidence_refs_json TEXT NOT NULL, challenge_hash TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS yank_reviews (
          arbitration_id TEXT PRIMARY KEY REFERENCES yank_arbitrations(arbitration_id),
          reviewer_id TEXT NOT NULL, finding TEXT NOT NULL CHECK(finding IN ('SUBSTANTIATED','NOT_SUBSTANTIATED')),
          rationale TEXT NOT NULL, evidence_refs_json TEXT NOT NULL, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS yank_reruns (
          arbitration_id TEXT PRIMARY KEY REFERENCES yank_arbitrations(arbitration_id),
          action TEXT NOT NULL CHECK(action IN ('PASS','REWRITE','YANK','UNAVAILABLE')),
          output_hash TEXT, result_json TEXT NOT NULL, completed_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS yank_scar_receipts (
          sequence INTEGER PRIMARY KEY AUTOINCREMENT, arbitration_id TEXT NOT NULL REFERENCES yank_arbitrations(arbitration_id),
          event_type TEXT NOT NULL, event_id TEXT NOT NULL UNIQUE, event_hash TEXT NOT NULL,
          signature TEXT NOT NULL, timestamp TEXT NOT NULL, event_json TEXT NOT NULL
        );
        CREATE TRIGGER IF NOT EXISTS yank_challenges_no_update BEFORE UPDATE ON yank_challenges
          BEGIN SELECT RAISE(ABORT,'immutable challenge'); END;
        CREATE TRIGGER IF NOT EXISTS yank_challenges_no_delete BEFORE DELETE ON yank_challenges
          BEGIN SELECT RAISE(ABORT,'immutable challenge'); END;
        CREATE TRIGGER IF NOT EXISTS yank_reviews_no_update BEFORE UPDATE ON yank_reviews
          BEGIN SELECT RAISE(ABORT,'immutable review'); END;
        CREATE TRIGGER IF NOT EXISTS yank_reviews_no_delete BEFORE DELETE ON yank_reviews
          BEGIN SELECT RAISE(ABORT,'immutable review'); END;
        CREATE TRIGGER IF NOT EXISTS yank_reruns_no_update BEFORE UPDATE ON yank_reruns
          BEGIN SELECT RAISE(ABORT,'immutable rerun'); END;
        CREATE TRIGGER IF NOT EXISTS yank_reruns_no_delete BEFORE DELETE ON yank_reruns
          BEGIN SELECT RAISE(ABORT,'immutable rerun'); END;
        CREATE TRIGGER IF NOT EXISTS yank_scar_no_update BEFORE UPDATE ON yank_scar_receipts
          BEGIN SELECT RAISE(ABORT,'immutable SCAR receipt'); END;
        CREATE TRIGGER IF NOT EXISTS yank_scar_no_delete BEFORE DELETE ON yank_scar_receipts
          BEGIN SELECT RAISE(ABORT,'immutable SCAR receipt'); END;
        """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            try:
                self._db.execute("BEGIN IMMEDIATE")
                yield self._db
                self._db.execute("COMMIT")
            except Exception:
                if self._db.in_transaction:
                    self._db.execute("ROLLBACK")
                raise

    def _append_evidence(self, db: sqlite3.Connection, *, arbitration_id: str, task_id: str,
                         event_type: str, actor_id: str, why: str, result: str,
                         metadata: Mapping[str, Any]) -> None:
        timestamp = _utc_now()
        event: dict[str, Any] = {
            "event": event_type, "task_id": task_id, "timestamp": timestamp,
            "who": actor_id, "what": event_type, "when": timestamp,
            "where": "backend.coordination.yank_procedural_review", "why": why,
            "how": "server-side policy checks + SQLite BEGIN IMMEDIATE + signed SCAR append",
            "authorization": "verified_by_injected_backend_policy",
            "memory_loaded": "UNKNOWN", "network_accessed": "UNKNOWN", "files_changed": [],
            "result": result, "arbitration_id": arbitration_id, "metadata": dict(metadata),
        }
        event["event_hash"] = "sha256:" + hashlib.sha256(_canonical(event)).hexdigest()
        try:
            receipt = self._evidence_sink(event)
        except Exception as exc:
            raise YANKEvidenceError("mandatory SCAR append failed; transition rolled back") from exc
        event_id = getattr(receipt, "event_id", None)
        event_hash = getattr(receipt, "event_hash", None)
        signature = getattr(receipt, "signature", None)
        sequence = getattr(receipt, "sequence", None)
        receipt_type = getattr(receipt, "event_type", event_type)
        if (receipt_type != event_type or not isinstance(event_id, str) or not event_id.strip()
            or not isinstance(event_hash, str) or not re.fullmatch(r"[0-9a-f]{64}", event_hash)
            or not isinstance(signature, str) or not signature.strip()
            or type(sequence) is not int or sequence < 0):
            raise YANKEvidenceError("SCAR sink returned no valid signed event receipt")
        db.execute(
            "INSERT INTO yank_scar_receipts (arbitration_id,event_type,event_id,event_hash,signature,timestamp,event_json) "
            "VALUES (?,?,?,?,?,?,?)",
            (arbitration_id, event_type, event_id, event_hash, signature, timestamp,
             json.dumps(event, sort_keys=True, separators=(",", ":"))),
        )

    def create_yank_arbitration(self, *, arbitration_id: str, task_id: str,
                                initiator_ids: Sequence[str], candidate_hash: str,
                                original_action: str = "YANK",
                                reason: str = "Original arbitration returned YANK; output withheld") -> dict[str, Any]:
        """Persist a YANK escrow record from trusted arbitration code only."""
        arbitration_id = _required_text(arbitration_id, "arbitration_id")
        task_id = _required_text(task_id, "task_id")
        if isinstance(initiator_ids, (str, bytes)) or not isinstance(initiator_ids, Sequence):
            raise ValueError("initiator_ids must be a sequence")
        initiators = tuple(dict.fromkeys(_required_text(x, "initiator_id") for x in initiator_ids))
        if not initiators:
            raise ValueError("at least one attributable YANK initiator is required")
        if not isinstance(candidate_hash, str) or not SHA3_512_RE.fullmatch(candidate_hash):
            raise ValueError("candidate_hash must be a sha3-512 digest")
        if str(original_action).upper() != "YANK":
            raise YANKReviewDenied("procedural fallback review is only available for YANK")
        now = _utc_now()
        with self._transaction() as db:
            try:
                db.execute(
                    "INSERT INTO yank_arbitrations (arbitration_id,task_id,initiator_ids_json,candidate_hash,"
                    "original_action,state,created_at,updated_at) VALUES (?,?,?,?, 'YANK','ESCROWED',?,?)",
                    (arbitration_id, task_id, json.dumps(initiators), candidate_hash, now, now),
                )
            except sqlite3.IntegrityError as exc:
                raise YANKReviewConflict("arbitration already exists or violates the YANK contract") from exc
            self._append_evidence(
                db, arbitration_id=arbitration_id, task_id=task_id,
                event_type="YANK_ESCROW_REGISTERED", actor_id="system:yank-arbitration",
                why=reason, result="ESCROWED",
                metadata={"initiator_ids": list(initiators), "candidate_hash": candidate_hash},
            )
        return self.get_arbitration(arbitration_id)

    def file_challenge(self, arbitration_id: str, *, challenger_id: str, defect_category: str,
                       description: str, evidence_refs: Sequence[str]) -> dict[str, Any]:
        """File the sole procedural challenge; challenger must be a non-initiator."""
        arbitration_id = _required_text(arbitration_id, "arbitration_id")
        challenger_id = _required_text(challenger_id, "challenger_id")
        category = str(defect_category).upper()
        if category not in DEFECT_CATEGORIES:
            raise ValueError("unsupported procedural defect category")
        description = _required_text(description, "description", 2000)
        refs = _evidence_refs(evidence_refs)
        with self._transaction() as db:
            row = self._get_row(db, arbitration_id)
            initiators = tuple(_decode(row["initiator_ids_json"]))
            if challenger_id in initiators:
                raise YANKReviewDenied("original YANK initiator cannot challenge their own arbitration")
            try:
                participant = self._participant_check(challenger_id, arbitration_id)
            except Exception as exc:
                raise YANKReviewDenied("participant registry verification failed") from exc
            if participant is not True:
                raise YANKReviewDenied("challenger is not a verified arbitration participant")
            if row["state"] != "ESCROWED" or row["challenge_count"] != 0:
                raise YANKReviewConflict("only one challenge is permitted while the YANK is escrowed")
            now = _utc_now()
            doc = {"arbitration_id": arbitration_id, "challenger_id": challenger_id,
                   "defect_category": category, "description": description,
                   "evidence_refs": list(refs), "created_at": now}
            digest = "sha3-512:" + hashlib.sha3_512(_canonical(doc)).hexdigest()
            db.execute(
                "INSERT INTO yank_challenges (arbitration_id,challenger_id,defect_category,description,"
                "evidence_refs_json,challenge_hash,created_at) VALUES (?,?,?,?,?,?,?)",
                (arbitration_id, challenger_id, category, description, json.dumps(refs), digest, now),
            )
            updated = db.execute(
                "UPDATE yank_arbitrations SET state='CHALLENGE_FILED',challenge_count=1,updated_at=? "
                "WHERE arbitration_id=? AND state='ESCROWED' AND challenge_count=0",
                (now, arbitration_id),
            )
            if updated.rowcount != 1:
                raise YANKReviewConflict("challenge transition lost a concurrent state race")
            self._append_evidence(
                db, arbitration_id=arbitration_id, task_id=row["task_id"],
                event_type="YANK_PROCEDURAL_CHALLENGE_FILED", actor_id=challenger_id,
                why="Participant filed one bounded challenge citing a specific procedural defect",
                result="CHALLENGE_FILED",
                metadata={"initiator_ids": list(initiators), "defect_category": category,
                          "challenge_hash": digest, "evidence_refs": list(refs)},
            )
        return self.get_arbitration(arbitration_id)

    def review_challenge(self, arbitration_id: str, *, reviewer_id: str, finding: str,
                         rationale: str, evidence_refs: Sequence[str]) -> dict[str, Any]:
        """Perform the sole independent procedural review; never judge merits."""
        arbitration_id = _required_text(arbitration_id, "arbitration_id")
        reviewer_id = _required_text(reviewer_id, "reviewer_id")
        finding = str(finding).upper()
        if finding not in REVIEW_FINDINGS:
            raise ValueError("finding must be SUBSTANTIATED or NOT_SUBSTANTIATED")
        rationale = _required_text(rationale, "rationale", 2000)
        refs = _evidence_refs(evidence_refs)
        with self._transaction() as db:
            row = self._get_row(db, arbitration_id)
            challenge = db.execute("SELECT * FROM yank_challenges WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            if row["state"] != "CHALLENGE_FILED" or challenge is None or row["review_count"] != 0:
                raise YANKReviewConflict("one review is permitted only after a valid challenge")
            initiators = tuple(_decode(row["initiator_ids_json"]))
            challenger = challenge["challenger_id"]
            if reviewer_id == challenger or reviewer_id in initiators:
                raise YANKReviewDenied("reviewer must be independent of initiator and challenger")
            try:
                independent = self._reviewer_check(reviewer_id, arbitration_id, challenger, initiators)
            except Exception as exc:
                raise YANKReviewDenied("reviewer authorization verification failed") from exc
            if independent is not True:
                raise YANKReviewDenied("reviewer is not independently authorized")
            now = _utc_now()
            next_state = "READY_FOR_RERUN" if finding == "SUBSTANTIATED" else "HELD_FOR_HUMAN_ESCALATION"
            db.execute(
                "INSERT INTO yank_reviews (arbitration_id,reviewer_id,finding,rationale,evidence_refs_json,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (arbitration_id, reviewer_id, finding, rationale, json.dumps(refs), now),
            )
            updated = db.execute(
                "UPDATE yank_arbitrations SET state=?,review_count=1,updated_at=? "
                "WHERE arbitration_id=? AND state='CHALLENGE_FILED' AND review_count=0",
                (next_state, now, arbitration_id),
            )
            if updated.rowcount != 1:
                raise YANKReviewConflict("review transition lost a concurrent state race")
            self._append_evidence(
                db, arbitration_id=arbitration_id, task_id=row["task_id"],
                event_type="YANK_PROCEDURAL_REVIEW_COMPLETED", actor_id=reviewer_id,
                why="Independent reviewer assessed only the cited procedural defect",
                result=finding,
                metadata={"challenger_id": challenger, "defect_category": challenge["defect_category"],
                          "rationale": rationale, "evidence_refs": list(refs), "next_state": next_state},
            )
        return self.get_arbitration(arbitration_id)

    def rerun_original_arbitration(self, arbitration_id: str, *, requester_id: str,
                                   rerun_handler: RerunHandler) -> dict[str, Any]:
        """Rerun the original arbitration once; PASS does not release output."""
        arbitration_id = _required_text(arbitration_id, "arbitration_id")
        requester_id = _required_text(requester_id, "requester_id")
        if not callable(rerun_handler):
            raise TypeError("rerun_handler must be callable")
        with self._transaction() as db:
            row = self._get_row(db, arbitration_id)
            if row["state"] != "READY_FOR_RERUN" or row["review_count"] != 1:
                raise YANKReviewConflict("rerun requires a substantiated review")
            if row["rerun_count"] != 0:
                raise YANKReviewConflict("the original arbitration may be rerun only once")
            try:
                authorized = self._rerun_authorizer(requester_id, arbitration_id, row["task_id"])
            except Exception as exc:
                raise YANKReviewDenied("Gate rerun authorization verification failed") from exc
            if authorized is not True:
                raise YANKReviewDenied("Gate authorization is required for the original arbitration rerun")
            challenge = db.execute("SELECT * FROM yank_challenges WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            review = db.execute("SELECT * FROM yank_reviews WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            snapshot = {
                "arbitration_id": arbitration_id, "task_id": row["task_id"],
                "initiator_ids": _decode(row["initiator_ids_json"]), "original_action": row["original_action"],
                "original_candidate_hash": row["candidate_hash"],
                "challenge": {"challenger_id": challenge["challenger_id"],
                              "defect_category": challenge["defect_category"],
                              "description": challenge["description"],
                              "evidence_refs": _decode(challenge["evidence_refs_json"])},
                "review": {"reviewer_id": review["reviewer_id"], "finding": review["finding"],
                           "rationale": review["rationale"],
                           "evidence_refs": _decode(review["evidence_refs_json"])},
            }
            now = _utc_now()
            updated = db.execute(
                "UPDATE yank_arbitrations SET state='RERUN_IN_PROGRESS',rerun_count=1,updated_at=? "
                "WHERE arbitration_id=? AND state='READY_FOR_RERUN' AND rerun_count=0",
                (now, arbitration_id),
            )
            if updated.rowcount != 1:
                raise YANKReviewConflict("rerun transition lost a concurrent state race")
            self._append_evidence(
                db, arbitration_id=arbitration_id, task_id=row["task_id"],
                event_type="YANK_PROCEDURAL_RERUN_STARTED", actor_id=requester_id,
                why="Substantiated procedural defect permits one rerun of the original arbitration",
                result="RERUN_IN_PROGRESS",
                metadata={"original_candidate_hash": row["candidate_hash"],
                          "reviewer_id": review["reviewer_id"], "gate_authorized": True},
            )

        # Persisted RERUN_IN_PROGRESS consumes the single attempt before provider work.
        try:
            raw = rerun_handler(snapshot)
            if not isinstance(raw, Mapping):
                raise ValueError("rerun handler returned a non-mapping result")
            action = str(raw.get("action", "")).upper()
            if action not in RERUN_ACTIONS:
                raise ValueError("rerun handler returned an unsupported action")
            output_hash = raw.get("output_hash")
            if output_hash is not None and (
                not isinstance(output_hash, str) or not SHA3_512_RE.fullmatch(output_hash)
            ):
                raise ValueError("rerun output_hash must be a sha3-512 digest")
            result_doc = {"action": action, "output_hash": output_hash, "result_ref": raw.get("result_ref")}
        except Exception as exc:
            action, output_hash = "UNAVAILABLE", None
            result_doc = {"action": action, "error_type": type(exc).__name__}

        final_state = "RESOLVED" if action == "PASS" else "HELD_FOR_HUMAN_ESCALATION"
        with self._transaction() as db:
            row = self._get_row(db, arbitration_id)
            if row["state"] != "RERUN_IN_PROGRESS" or row["rerun_count"] != 1:
                raise YANKReviewConflict("rerun state changed unexpectedly; fail closed")
            completed = _utc_now()
            db.execute(
                "INSERT INTO yank_reruns (arbitration_id,action,output_hash,result_json,completed_at) "
                "VALUES (?,?,?,?,?)",
                (arbitration_id, action, output_hash,
                 json.dumps(result_doc, sort_keys=True, separators=(",", ":")), completed),
            )
            updated = db.execute(
                "UPDATE yank_arbitrations SET state=?,updated_at=? "
                "WHERE arbitration_id=? AND state='RERUN_IN_PROGRESS' AND rerun_count=1",
                (final_state, completed, arbitration_id),
            )
            if updated.rowcount != 1:
                raise YANKReviewConflict("rerun completion lost a concurrent state race")
            self._append_evidence(
                db, arbitration_id=arbitration_id, task_id=row["task_id"],
                event_type="YANK_PROCEDURAL_RERUN_COMPLETED", actor_id=requester_id,
                why="Original arbitration rerun completed; output remains subject to normal Gate 2 release",
                result=action,
                metadata={"output_hash": output_hash, "final_state": final_state, "rerun_count": 1,
                          "result_ref": result_doc.get("result_ref"), "error_type": result_doc.get("error_type")},
            )
        return self.get_arbitration(arbitration_id)

    def get_arbitration(self, arbitration_id: str) -> dict[str, Any]:
        arbitration_id = _required_text(arbitration_id, "arbitration_id")
        with self._lock:
            row = self._get_row(self._db, arbitration_id)
            challenge = self._db.execute("SELECT * FROM yank_challenges WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            review = self._db.execute("SELECT * FROM yank_reviews WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            rerun = self._db.execute("SELECT * FROM yank_reruns WHERE arbitration_id=?", (arbitration_id,)).fetchone()
            receipts = self._db.execute(
                "SELECT event_type,event_id,event_hash,signature,sequence,timestamp "
                "FROM yank_scar_receipts WHERE arbitration_id=? ORDER BY sequence", (arbitration_id,)
            ).fetchall()
        return {
            "arbitration_id": row["arbitration_id"], "task_id": row["task_id"],
            "initiator_ids": _decode(row["initiator_ids_json"]), "candidate_hash": row["candidate_hash"],
            "state": row["state"], "challenge_count": row["challenge_count"],
            "review_count": row["review_count"], "rerun_count": row["rerun_count"],
            "created_at": row["created_at"], "updated_at": row["updated_at"],
            "challenge": None if challenge is None else {
                "challenger_id": challenge["challenger_id"], "defect_category": challenge["defect_category"],
                "description": challenge["description"], "evidence_refs": _decode(challenge["evidence_refs_json"]),
                "challenge_hash": challenge["challenge_hash"], "created_at": challenge["created_at"]},
            "review": None if review is None else {
                "reviewer_id": review["reviewer_id"], "finding": review["finding"],
                "rationale": review["rationale"], "evidence_refs": _decode(review["evidence_refs_json"]),
                "created_at": review["created_at"]},
            "rerun": None if rerun is None else {
                "action": rerun["action"], "output_hash": rerun["output_hash"],
                "result": _decode(rerun["result_json"]), "completed_at": rerun["completed_at"]},
            "scar_receipts": [dict(item) for item in receipts],
            "output_released": False,
        }

    @staticmethod
    def _get_row(db: sqlite3.Connection, arbitration_id: str) -> sqlite3.Row:
        row = db.execute("SELECT * FROM yank_arbitrations WHERE arbitration_id=?", (arbitration_id,)).fetchone()
        if row is None:
            raise YANKReviewDenied("unknown arbitration; no fallback review state exists")
        return row
