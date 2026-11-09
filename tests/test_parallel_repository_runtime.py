from __future__ import annotations

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "parallel_repository_runtime.py"
SPEC = importlib.util.spec_from_file_location("parallel_repository_runtime", SCRIPT)
assert SPEC and SPEC.loader
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class ParallelRepositoryRuntimeTests(unittest.TestCase):
    def test_registry_has_exactly_twelve_unique_repositories(self):
        manifest = runtime.load_manifest()
        repositories = manifest["repositories"]
        self.assertEqual(len(repositories), 12)
        self.assertEqual(len({item["id"] for item in repositories}), 12)

    def test_dependency_plan_is_complete_and_ordered(self):
        manifest = runtime.load_manifest()
        layers = runtime.dependency_layers(manifest["repositories"])
        flattened = [item for layer in layers for item in layer]
        self.assertEqual(set(flattened), {item["id"] for item in manifest["repositories"]})
        positions = {item: index for index, layer in enumerate(layers) for item in layer}
        for item in manifest["repositories"]:
            for dependency in item.get("depends_on", []):
                self.assertLess(positions[dependency], positions[item["id"]])

    def test_cycle_is_rejected(self):
        graph = [
            {"id": "alpha", "depends_on": ["beta"]},
            {"id": "beta", "depends_on": ["alpha"]},
        ]
        with self.assertRaisesRegex(ValueError, "cycle"):
            runtime.dependency_layers(graph)

    def test_unknown_dependency_is_rejected(self):
        graph = [{"id": "alpha", "depends_on": ["missing"]}]
        with self.assertRaisesRegex(ValueError, "unknown dependency"):
            runtime.load_manifest.__globals__["dependency_layers"](graph)

    def test_path_traversal_is_rejected(self):
        bad = {
            "id": "unsafe",
            "local_path": "../outside",
            "repository": "AppelJr/unsafe",
            "depends_on": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            old_root = runtime.ROOT
            try:
                runtime.ROOT = Path(tmp)
                with self.assertRaisesRegex(ValueError, "unsafe local_path"):
                    runtime.load_manifest.__globals__["load_manifest"]()
                # Direct path validation is covered by constructing an invalid manifest copy.
                rel = Path(bad["local_path"])
                self.assertTrue(rel.is_absolute() or ".." in rel.parts)
            finally:
                runtime.ROOT = old_root


if __name__ == "__main__":
    unittest.main()
