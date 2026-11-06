use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AccessDecision { Allow, Deny }

fn decision_code(decision: AccessDecision) -> &'static str {
    match decision { AccessDecision::Allow => "allow", AccessDecision::Deny => "deny" }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EvaluationClock { now: u64 }
impl EvaluationClock {
    pub fn fixed(now: u64) -> Self { Self { now } }
    pub fn now(&self) -> u64 { self.now }
    pub fn system() -> Result<Self, AuthorizationError> {
        Ok(Self { now: SystemTime::now().duration_since(UNIX_EPOCH).map_err(|_| AuthorizationError::Clock)?.as_secs() })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identity { pub id: String, pub branches: Vec<String> }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub subject: String,
    pub resource: String,
    pub branch: String,
    pub granted_by: String,
    pub expires_at: Option<u64>,
    pub revoked: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AuthorizationError { UnknownIdentity, UnknownResource, UnauthorizedIssuer, Expired, Revoked, Clock }

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuditEvent {
    pub sequence: u64,
    pub grant_id: String,
    pub subject: String,
    pub resource: String,
    pub decision: String,
    pub reason: String,
    pub timestamp: u64,
    pub previous_hash: String,
    pub hash: String,
}

fn canonical_event_bytes(e: &AuditEvent) -> Vec<u8> {
    serde_json::to_vec(&(
        e.sequence, &e.grant_id, &e.subject, &e.resource, &e.decision,
        &e.reason, e.timestamp, &e.previous_hash
    )).expect("audit event serialization must be infallible")
}
fn event_hash(e: &AuditEvent) -> String {
    let mut h = Sha256::new(); h.update(canonical_event_bytes(e)); format!("{:x}", h.finalize())
}

#[derive(Default)]
pub struct AuditLedger { events: Vec<AuditEvent> }
impl AuditLedger {
    pub fn append(&mut self, mut event: AuditEvent) -> Result<(), &'static str> {
        let expected_seq = self.events.len() as u64 + 1;
        if event.sequence != expected_seq { return Err("invalid sequence"); }
        event.previous_hash = self.events.last().map(|x| x.hash.clone()).unwrap_or_default();
        event.hash = event_hash(&event);
        self.events.push(event); Ok(())
    }
    pub fn events(&self) -> &[AuditEvent] { &self.events }
    pub fn verify_chain(events: &[AuditEvent]) -> bool {
        let mut prev = String::new();
        for (i, e) in events.iter().enumerate() {
            if e.sequence != i as u64 + 1 || e.previous_hash != prev || e.hash != event_hash(e) { return false; }
            prev = e.hash.clone();
        }
        true
    }
    pub fn import_verified(events: Vec<AuditEvent>) -> Result<Self, &'static str> {
        if !Self::verify_chain(&events) { return Err("invalid audit chain"); }
        Ok(Self { events })
    }
}

pub struct AuthorizationEngine {
    identities: HashMap<String, Identity>,
    grants: HashMap<String, Grant>,
    resources: HashMap<String, String>,
}

impl Default for AuthorizationEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorizationEngine {
    pub fn new() -> Self { Self { identities: HashMap::new(), grants: HashMap::new(), resources: HashMap::new() } }
    pub fn add_identity(&mut self, identity: Identity) -> Result<(), &'static str> {
        if identity.id.is_empty() || self.identities.contains_key(&identity.id) { return Err("invalid or duplicate identity"); }
        self.identities.insert(identity.id.clone(), identity); Ok(())
    }
    pub fn add_resource(&mut self, resource: impl Into<String>, branch: impl Into<String>) -> Result<(), &'static str> {
        let resource = resource.into(); let branch = branch.into();
        if resource.is_empty() || branch.is_empty() || self.resources.contains_key(&resource) { return Err("invalid or duplicate resource"); }
        self.resources.insert(resource, branch); Ok(())
    }
    pub fn add_grant(&mut self, grant: Grant) -> Result<(), &'static str> {
        if self.grants.contains_key(&grant.id) || !self.identities.contains_key(&grant.subject) { return Err("invalid or duplicate grant"); }
        let branch = self.resources.get(&grant.resource).ok_or("unknown resource")?;
        let issuer = self.identities.get(&grant.granted_by).ok_or("unknown issuer")?;
        if branch != &grant.branch || !issuer.branches.iter().any(|b| b == branch) { return Err("issuer lacks grant authority"); }
        self.grants.insert(grant.id.clone(), grant); Ok(())
    }
    pub fn authorize(&self, grant_id: &str, clock: EvaluationClock) -> AccessDecision {
        self.authorize_checked(grant_id, clock).unwrap_or(AccessDecision::Deny)
    }
    pub fn authorize_checked(&self, grant_id: &str, clock: EvaluationClock) -> Result<AccessDecision, AuthorizationError> {
        let grant = self.grants.get(grant_id).ok_or(AuthorizationError::UnknownResource)?;
        if !self.identities.contains_key(&grant.subject) { return Err(AuthorizationError::UnknownIdentity); }
        if !self.resources.contains_key(&grant.resource) { return Err(AuthorizationError::UnknownResource); }
        if grant.revoked { return Err(AuthorizationError::Revoked); }
        if grant.expires_at.is_some_and(|t| clock.now() >= t) { return Err(AuthorizationError::Expired); }
        Ok(AccessDecision::Allow)
    }
    pub fn grant(&self, id: &str) -> Option<&Grant> { self.grants.get(id) }
}

pub fn make_audit_event(seq: u64, grant: &Grant, decision: AccessDecision, reason: impl Into<String>, timestamp: u64) -> AuditEvent {
    AuditEvent { sequence: seq, grant_id: grant.id.clone(), subject: grant.subject.clone(), resource: grant.resource.clone(), decision: decision_code(decision).to_string(), reason: reason.into(), timestamp, previous_hash: String::new(), hash: String::new() }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> (AuthorizationEngine, Grant) {
        let mut e = AuthorizationEngine::new();
        e.add_identity(Identity { id: "owner".into(), branches: vec!["main".into()] }).unwrap();
        e.add_identity(Identity { id: "user".into(), branches: vec![] }).unwrap();
        e.add_resource("vault", "main").unwrap();
        let g = Grant { id: "g1".into(), subject: "user".into(), resource: "vault".into(), branch: "main".into(), granted_by: "owner".into(), expires_at: Some(100), revoked: false };
        e.add_grant(g.clone()).unwrap(); (e,g)
    }
    #[test] fn expiry_and_boundary() { let (e,_) = fixture(); assert_eq!(e.authorize("g1", EvaluationClock::fixed(99)), AccessDecision::Allow); assert_eq!(e.authorize("g1", EvaluationClock::fixed(100)), AccessDecision::Deny); }
    #[test] fn issuer_must_control_branch() { let mut e = AuthorizationEngine::new(); e.add_identity(Identity { id:"user".into(), branches:vec![] }).unwrap(); e.add_resource("r","main").unwrap(); assert!(e.add_grant(Grant{id:"g".into(),subject:"user".into(),resource:"r".into(),branch:"main".into(),granted_by:"user".into(),expires_at:None,revoked:false}).is_err()); }
    #[test] fn revocation_is_enforced() { let (mut e,g) = fixture(); let mut r=g.clone(); r.revoked=true; e.grants.insert(r.id.clone(),r); assert_eq!(e.authorize("g1",EvaluationClock::fixed(0)),AccessDecision::Deny); }
    #[test] fn canonical_audit_chain_is_stable() { let (_,g)=fixture(); let mut l=AuditLedger::default(); l.append(make_audit_event(1,&g,AccessDecision::Allow,"granted",1)).unwrap(); l.append(make_audit_event(2,&g,AccessDecision::Deny,"expired",100)).unwrap(); assert!(AuditLedger::verify_chain(l.events())); let mut tampered=l.events().to_vec(); tampered[1].decision="deny".into(); tampered[1].hash=String::from("bad"); assert!(!AuditLedger::verify_chain(&tampered)); assert_eq!(l.events()[0].decision,"allow"); }
    #[test] fn verified_import_is_tamper_boundary() { let (_,g)=fixture(); let mut l=AuditLedger::default(); l.append(make_audit_event(1,&g,AccessDecision::Allow,"granted",1)).unwrap(); assert!(AuditLedger::import_verified(l.events().to_vec()).is_ok()); }
}




use chrono::{
    DateTime, FixedOffset, Local, SecondsFormat, Utc,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum TulipError {
    #[error("invalid card: {0}")]
    InvalidCard(&'static str),

    #[error("invalid receipt log")]
    InvalidReceiptLog,

    #[error("this gate has already received a choice")]
    AlreadyChosen,

    #[error("a different choice was already recorded for this Tulip ID")]
    ConflictingChoice,

    #[error("invalid device ID")]
    InvalidDeviceId,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Lane {
    Playground,
    Smoke,
    #[serde(rename = "Real-Prod-Live")]
    RealProdLive,
    Production,
}

impl Lane {
    pub fn as_str(self) -> &'static str {
        match self {
            Lane::Playground => "Playground",
            Lane::Smoke => "Smoke",
            Lane::RealProdLive => "Real-Prod-Live",
            Lane::Production => "Production",
        }
    }

    pub fn next(self) -> Option<Self> {
        match self {
            Lane::Playground => Some(Lane::Smoke),
            Lane::Smoke => Some(Lane::RealProdLive),
            Lane::RealProdLive => Some(Lane::Production),
            Lane::Production => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampPair {
    pub utc: DateTime<Utc>,
    pub local: DateTime<FixedOffset>,
}

impl TimestampPair {
    pub fn now() -> Self {
        let local = Local::now().fixed_offset();
        let utc = local.with_timezone(&Utc);
        Self { utc, local }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceStep {
    /// A short factual statement about an observed event, rule, or data access.
    pub statement: String,

    /// Identifier for the event, rule, or data record supporting this step.
    pub evidence_ref: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionTrace {
    /// Exact user utterance or a stable identifier for a system event.
    pub trigger: String,

    /// Ordered, evidence-referenced decision steps.
    pub steps: Vec<TraceStep>,

    /// Concise summary of the policy outcome and proposed action.
    pub decision_point: String,

    /// Explicit unresolved facts; empty means none were identified.
    pub open_questions: Vec<String>,

    /// Must be recorded before the card is presented.
    pub generated_at: DateTime<Utc>,
}

impl DecisionTrace {
    fn validate(&self, presented_at: DateTime<Utc>) -> Result<(), TulipError> {
        if self.trigger.trim().is_empty() {
            return Err(TulipError::InvalidCard("trace trigger is empty"));
        }
        if self.steps.is_empty() {
            return Err(TulipError::InvalidCard("trace has no steps"));
        }
        if self.steps.iter().any(|s| {
            s.statement.trim().is_empty() || s.evidence_ref.trim().is_empty()
        }) {
            return Err(TulipError::InvalidCard(
                "each trace step needs a statement and evidence reference",
            ));
        }
        if self.decision_point.trim().is_empty() {
            return Err(TulipError::InvalidCard("decision point is empty"));
        }
        if self.generated_at > presented_at {
            return Err(TulipError::InvalidCard(
                "trace must be generated before card presentation",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmokeTest {
    pub test_id: String,
    pub description: String,
    pub lane: Lane,
    pub expected_result: String,

    /// Must be false for tests eligible to run after this card's Accept.
    pub external_side_effect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GateCard {
    pub tulip_id: Uuid,
    pub gate_name: String,
    pub stage: Lane,
    pub timestamp: TimestampPair,
    pub presented_at: DateTime<Utc>,

    pub proposed_action: String,
    pub target: Option<String>,

    pub trace: DecisionTrace,

    pub risks: Vec<String>,
    pub rewards: Vec<String>,
    pub pros: Vec<String>,
    pub cons: Vec<String>,

    pub smoke_tests: Vec<SmokeTest>,
}

impl GateCard {
    pub fn new(
        gate_name: impl Into<String>,
        stage: Lane,
        proposed_action: impl Into<String>,
        target: Option<String>,
        trace: DecisionTrace,
        risks: Vec<String>,
        rewards: Vec<String>,
        pros: Vec<String>,
        cons: Vec<String>,
        smoke_tests: Vec<SmokeTest>,
    ) -> Result<Self, TulipError> {
        let card = Self {
            tulip_id: Uuid::new_v4(),
            gate_name: gate_name.into(),
            stage,
            timestamp: TimestampPair::now(),
            presented_at: Utc::now(),
            proposed_action: proposed_action.into(),
            target,
            trace,
            risks,
            rewards,
            pros,
            cons,
            smoke_tests,
        };
        card.validate()?;
        Ok(card)
    }

    pub fn validate(&self) -> Result<(), TulipError> {
        if self.gate_name.trim().is_empty() {
            return Err(TulipError::InvalidCard("gate name is empty"));
        }
        if self.proposed_action.trim().is_empty() {
            return Err(TulipError::InvalidCard("proposed action is empty"));
        }

        self.trace.validate(self.presented_at)?;

        for test in &self.smoke_tests {
            if test.test_id.trim().is_empty()
                || test.description.trim().is_empty()
                || test.expected_result.trim().is_empty()
            {
                return Err(TulipError::InvalidCard(
                    "smoke tests require an ID, description, and expected result",
                ));
            }
            if test.lane != self.stage {
                return Err(TulipError::InvalidCard(
                    "smoke-test lane must match the card stage",
                ));
            }
            if test.external_side_effect {
                return Err(TulipError::InvalidCard(
                    "externally side-effecting tests require a separate gate",
                ));
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Choice {
    Accept,
    Decline,
    Discuss,
}

impl Choice {
    fn as_str(self) -> &'static str {
        match self {
            Choice::Accept => "ACCEPT",
            Choice::Decline => "DECLINE",
            Choice::Discuss => "DISCUSS",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    pub tulip_id: Uuid,
    pub choice: Choice,
    pub ts: DateTime<Utc>,
    pub device_id: String,
    pub gate: String,

    /// Additional integrity-chain fields.
    pub sequence: u64,
    pub previous_hash: String,
    pub receipt_hash: String,
}

impl Receipt {
    fn calculate_hash(&self) -> String {
        let fields = [
            self.sequence.to_string(),
            self.tulip_id.to_string(),
            self.choice.as_str().to_owned(),
            self.ts.to_rfc3339_opts(SecondsFormat::Nanos, true),
            self.device_id.clone(),
            self.gate.clone(),
            self.previous_hash.clone(),
        ];

        // Length-prefix each field so delimiters inside values cannot
        // create ambiguous encodings.
        let mut hasher = Sha256::new();
        for field in fields {
            let bytes = field.as_bytes();
            hasher.update((bytes.len() as u64).to_be_bytes());
            hasher.update(bytes);
        }

        format!("{:x}", hasher.finalize())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct ReceiptLog {
    pub receipts: Vec<Receipt>,
}

impl ReceiptLog {
    pub fn append(
        &mut self,
        card: &GateCard,
        choice: Choice,
        ts: DateTime<Utc>,
        device_id: String,
    ) -> Result<Receipt, TulipError> {
        if device_id.trim().is_empty()
            || device_id.len() > 128
            || device_id.chars().any(char::is_whitespace)
        {
            return Err(TulipError::InvalidDeviceId);
        }

        // Idempotency: a retry of the same card/choice returns the
        // existing receipt; a conflicting choice is rejected.
        if let Some(existing) = self
            .receipts
            .iter()
            .find(|r| r.tulip_id == card.tulip_id)
        {
            if existing.choice == choice {
                return Ok(existing.clone());
            }
            return Err(TulipError::ConflictingChoice);
        }

        let previous_hash = self
            .receipts
            .last()
            .map(|r| r.receipt_hash.clone())
            .unwrap_or_else(|| "GENESIS".to_owned());

        let mut receipt = Receipt {
            tulip_id: card.tulip_id,
            choice,
            ts,
            device_id,
            gate: format!("{}:{}", card.gate_name, card.stage.as_str()),
            sequence: self.receipts.len() as u64,
            previous_hash,
            receipt_hash: String::new(),
        };

        receipt.receipt_hash = receipt.calculate_hash();
        self.receipts.push(receipt.clone());
        Ok(receipt)
    }

    pub fn verify(&self) -> Result<(), TulipError> {
        let mut expected_previous = "GENESIS".to_owned();

        for (index, receipt) in self.receipts.iter().enumerate() {
            if receipt.sequence != index as u64
                || receipt.previous_hash != expected_previous
                || receipt.receipt_hash != receipt.calculate_hash()
            {
                return Err(TulipError::InvalidReceiptLog);
            }

            expected_previous = receipt.receipt_hash.clone();
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct ChoiceOutcome {
    pub receipt: Receipt,

    /// Accept advances the stage only; `None` means Production is terminal.
    pub next_stage: Option<Lane>,

    /// Indicates that the listed, non-side-effecting smoke tests are
    /// eligible to run. This code does not execute them.
    pub smoke_tests_eligible: bool,

    /// Discuss opens the current thread; this code does not implement the UI.
    pub open_discussion: bool,
}

pub struct GateSession {
    pub card: GateCard,
    chosen: bool,
}

impl GateSession {
    pub fn present(card: GateCard) -> Result<Self, TulipError> {
        card.validate()?;
        Ok(Self {
            card,
            chosen: false,
        })
    }

    pub fn choose(
        &mut self,
        choice: Choice,
        device_id: String,
        receipt_log: &mut ReceiptLog,
    ) -> Result<ChoiceOutcome, TulipError> {
        if self.chosen {
            return Err(TulipError::AlreadyChosen);
        }

        let receipt = receipt_log.append(
            &self.card,
            choice,
            Utc::now(),
            device_id,
        )?;

        self.chosen = true;

        Ok(ChoiceOutcome {
            receipt,
            next_stage: if choice == Choice::Accept {
                self.card.stage.next()
            } else {
                None
            },
            smoke_tests_eligible: choice == Choice::Accept
                && !self.card.smoke_tests.is_empty(),
            open_discussion: choice == Choice::Discuss,
        })
    }
}

// ---------- Fenced-block language classification ----------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisplayLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Json,
    Bash,
    Html,
    Css,
    Markdown,
    PlainText,
}

impl DisplayLanguage {
    pub fn as_str(self) -> &'static str {
        match self {
            DisplayLanguage::Rust => "rust",
            DisplayLanguage::Python => "python",
            DisplayLanguage::JavaScript => "javascript",
            DisplayLanguage::TypeScript => "typescript",
            DisplayLanguage::Json => "json",
            DisplayLanguage::Bash => "bash",
            DisplayLanguage::Html => "html",
            DisplayLanguage::Css => "css",
            DisplayLanguage::Markdown => "markdown",
            DisplayLanguage::PlainText => "text",
        }
    }
}

/// Determines a display hint only. This function never executes content.
///
/// An explicit but unknown tag falls back to plain text; it does not fall
/// through to extension-based guessing.
pub fn classify_fence(
    info_string: Option<&str>,
    associated_path: Option<&str>,
) -> DisplayLanguage {
    if let Some(info) = info_string {
        let token = info.split_whitespace().next().unwrap_or("");
        if token.is_empty() {
            return extension_language(associated_path)
                .unwrap_or(DisplayLanguage::PlainText);
        }
        return match token.to_ascii_lowercase().as_str() {
            "rs" | "rust" => DisplayLanguage::Rust,
            "py" | "python" => DisplayLanguage::Python,
            "js" | "javascript" | "jsx" => DisplayLanguage::JavaScript,
            "ts" | "typescript" | "tsx" => DisplayLanguage::TypeScript,
            "json" => DisplayLanguage::Json,
            "sh" | "bash" | "shell" => DisplayLanguage::Bash,
            "html" | "htm" => DisplayLanguage::Html,
            "css" => DisplayLanguage::Css,
            "md" | "markdown" => DisplayLanguage::Markdown,
            _ => DisplayLanguage::PlainText,
        };
    }

    extension_language(associated_path).unwrap_or(DisplayLanguage::PlainText)
}

fn extension_language(path: Option<&str>) -> Option<DisplayLanguage> {
    let extension = path?.rsplit('.').next()?.to_ascii_lowercase();

    match extension.as_str() {
        "rs" => Some(DisplayLanguage::Rust),
        "py" => Some(DisplayLanguage::Python),
        "js" | "jsx" => Some(DisplayLanguage::JavaScript),
        "ts" | "tsx" => Some(DisplayLanguage::TypeScript),
        "json" => Some(DisplayLanguage::Json),
        "sh" | "bash" => Some(DisplayLanguage::Bash),
        "html" | "htm" => Some(DisplayLanguage::Html),
        "css" => Some(DisplayLanguage::Css),
        "md" => Some(DisplayLanguage::Markdown),
        _ => None,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FencedBlock {
    pub info_string: String,
    pub body: String,
    pub closed: bool,
}

/// Extracts fenced blocks for display. It does not parse or execute their
/// contents. An unclosed fence consumes the remaining input.
pub fn extract_fenced_blocks(input: &str) -> Vec<FencedBlock> {
    let lines: Vec<&str> = input.lines().collect();
    let mut blocks = Vec::new();
    let mut i = 0;

    while i < lines.len() {
        let Some((fence_char, fence_len, info)) = opening_fence(lines[i]) else {
            i += 1;
            continue;
        };

        let mut body_lines = Vec::new();
        i += 1;
        let mut closed = false;

        while i < lines.len() {
            if is_closing_fence(lines[i], fence_char, fence_len) {
                closed = true;
                i += 1;
                break;
            }

            body_lines.push(lines[i]);
            i += 1;
        }

        blocks.push(FencedBlock {
            info_string: info.to_owned(),
            body: body_lines.join("\n"),
            closed,
        });
    }

    blocks
}

fn opening_fence(line: &str) -> Option<(char, usize, &str)> {
    let trimmed = line.trim_start();
    let fence_char = trimmed.chars().next()?;

    if fence_char != '`' && fence_char != '~' {
        return None;
    }

    let fence_len = trimmed.chars().take_while(|&c| c == fence_char).count();
    if fence_len < 3 {
        return None;
    }

    let info = &trimmed[fence_len..];

    // Markdown does not allow backticks in a backtick-fence info string.
    if fence_char == '`' && info.contains('`') {
        return None;
    }

    Some((fence_char, fence_len, info.trim()))
}

fn is_closing_fence(line: &str, fence_char: char, min_len: usize) -> bool {
    let trimmed = line.trim_start();
    let count = trimmed.chars().take_while(|&c| c == fence_char).count();

    count >= min_len
        && trimmed.chars().skip(count).all(char::is_whitespace)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_explicit_language_falls_back_to_text() {
        assert_eq!(
            classify_fence(Some("unknown-runner"), Some("example.rs")),
            DisplayLanguage::PlainText
        );
    }

    #[test]
    fn absent_language_can_use_unambiguous_extension() {
        assert_eq!(
            classify_fence(None, Some("src/main.rs")),
            DisplayLanguage::Rust
        );
    }

    #[test]
    fn fenced_content_is_extracted_not_executed() {
        let blocks = extract_fenced_blocks("Example:\n```rust\nfn main() {}\n```\n");
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].info_string, "rust");
        assert_eq!(blocks[0].body, "fn main() {}");
        assert!(blocks[0].closed);
    }

    #[test]
    fn unclosed_fence_runs_to_end_of_input() {
        let blocks = extract_fenced_blocks("```text\nstill fenced");
        assert\_eq!(blocks.len(), 1);
        assert!(!blocks[0].closed);
        assert\_eq!(blocks[0].body, "still fenced");
    }

    #[test]
    fn receipt\_hash\_chain\_verifies() {
        let mut log = ReceiptLog::default();

        let receipt = Receipt {
            tulip\_id: Uuid::new\_v4(),
            choice: Choice::Accept,
            ts: Utc::now(),
            device\_id: "opaque-local-id".into(),
            gate: "Smoke:Smoke".into(),
            sequence: 0,
            previous\_hash: "GENESIS".into(),
            receipt\_hash: String::new(),
        };

        let mut receipt = receipt;
        receipt.receipt\_hash = receipt.calculate\_hash();
        log.receipts.push(receipt);

        assert!(log.verify().is\_ok());
    }
}
