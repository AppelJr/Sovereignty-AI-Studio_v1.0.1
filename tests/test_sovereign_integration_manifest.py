from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.validate_sovereign_integration import validate


class SovereignIntegrationManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "integration").mkdir()
        (self.root / "config").mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write_manifests(self, repositories: list[dict] | None = None) -> None:
        if repositories is None:
            repositories = [
                {
                    "repository": f"AppelJr/repo-{index:02d}",
                    "role": f"role-{index:02d}",
                    "integration_status": "DECLARED",
                    "test_status": "NOT_RUN",
                }
                for index in range(18)
            ]
        (self.root / "integration" / "repository-registry.json").write_text(
            json.dumps({
                "status": "declarative-integration-map",
                "canonical_runtime": "AppelJr/Sovereignty-AI-Studio_v1.0.1",
                "repositories": repositories,
            }),
            encoding="utf-8",
        )
        (self.root / "config" / "runtime-coherence.json").write_text(
            json.dumps({
                "ports": {
                    "python_bridge": 9897,
                    "dashboard": 9898,
                    "unified_server": 9899,
                },
                "state_policy": {
                    "default_mode": "local",
                    "implicit_fallback_disabled": True,
                    "private_state_is_not_committed": True,
                },
            }),
            encoding="utf-8",
        )

    def test_accepts_exact_eighteen_static_entries_without_claiming_release(self) -> None:
        self.write_manifests()
        report = validate(self.root)
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(report["repository_count"], 18)
        self.assertFalse(report["release_ready"])

    def test_rejects_wrong_repository_count(self) -> None:
        self.write_manifests([{
            "repository": "AppelJr/only-one",
            "role": "runtime",
        }])
        report = validate(self.root)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("expected exactly 18" in item for item in report["errors"]))

    def test_rejects_noncanonical_owner(self) -> None:
        entries = [
            {"repository": f"AppelJr/repo-{i}", "role": f"role-{i}"}
            for i in range(18)
        ]
        entries[0]["repository"] = "Appel420/legacy"
        self.write_manifests(entries)
        report = validate(self.root)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("canonical AppelJr" in item for item in report["errors"]))

    def test_rejects_duplicate_repository(self) -> None:
        entries = [
            {"repository": f"AppelJr/repo-{i}", "role": f"role-{i}"}
            for i in range(18)
        ]
        entries[1]["repository"] = entries[0]["repository"]
        self.write_manifests(entries)
        report = validate(self.root)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("duplicate repository" in item for item in report["errors"]))

    def test_rejects_implicit_fallback(self) -> None:
        self.write_manifests()
        path = self.root / "config" / "runtime-coherence.json"
        runtime = json.loads(path.read_text(encoding="utf-8"))
        runtime["state_policy"]["implicit_fallback_disabled"] = False
        path.write_text(json.dumps(runtime), encoding="utf-8")
        report = validate(self.root)
        self.assertEqual(report["status"], "FAIL")
        self.assertTrue(any("implicit fallback" in item for item in report["errors"]))


if __name__ == "__main__":
    unittest.main()
