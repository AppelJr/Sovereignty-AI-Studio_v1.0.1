import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "integration" / "browser" / "duckduckgo-privacy-extension.json"


class BrowserIntegrationManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = json.loads(MANIFEST.read_text(encoding="utf-8"))

    def test_external_component_is_not_authority(self):
        self.assertEqual(self.data["classification"], "external")
        self.assertFalse(self.data["authority"])
        self.assertFalse(self.data["browser_engine"])
        self.assertFalse(self.data["standalone_browser"])

    def test_default_state_fails_closed(self):
        policy = self.data["runtime_policy"]
        self.assertEqual(policy["default_state"], "BLOCKED")
        self.assertFalse(policy["local_mode_auto_install"])
        self.assertFalse(policy["remote_updates_auto_fetch")
        self.assertEqual(
            policy["extension_network_egress"],
            "REQUIRE_OWNER_APPROVAL_AND_POLICY_REVIEW",
        )

    def test_safari_is_separate_project(self):
        safari = self.data["targets"]["safari"]
        self.assertFalse(safari["supported_by_this_repository"])
        self.assertIn("privacy-essentials-safari", safari["separate_upstream_project"])


if __name__ == "__main__":
    unittest.main()
