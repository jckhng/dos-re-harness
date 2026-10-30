from __future__ import annotations

import contextlib
import hashlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from dos_re_harness.cli import build_parser


FIXTURE = Path(__file__).parent / "fixtures/minimal-project"


class CapturePlanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(FIXTURE, self.root / "project")
        self.plan = self.root / "capture.json"
        self.document = {"format_version": 1, "project": "project/project.json", "scenario": "boot"}

    def run_plan(self, *options):
        self.plan.write_text(json.dumps(self.document), encoding="utf-8")
        args = build_parser().parse_args([
            "capture-plan", str(self.plan), "--out-dir", str(self.root / "output"), *options,
        ])
        return args.func(args)

    def test_plan_dry_run_matches_existing_command_without_creating_output(self):
        planned = io.StringIO()
        with contextlib.redirect_stdout(planned):
            self.assertEqual(self.run_plan("--dry-run"), 0)
        direct = io.StringIO()
        args = build_parser().parse_args([
            "capture", str(self.root / "project/project.json"), "boot",
            "--out-dir", str(self.root / "output"), "--dry-run",
        ])
        with contextlib.redirect_stdout(direct):
            args.func(args)
        self.assertEqual(json.loads(planned.getvalue()), json.loads(direct.getvalue()))
        self.assertFalse((self.root / "output").exists())

    def test_invalid_plan_cannot_launch_adapter(self):
        for document in [
            {**self.document, "format_version": True},
            {**self.document, "typo": "ignored?"},
            {**self.document, "adapter_arguments": {"unknown": "x"}},
            {**self.document, "adapter_arguments": {"delay": True}},
            {**self.document, "adapter_arguments": {"delay": float("nan")}},
            {**self.document, "movie": "missing.json"},
        ]:
            with self.subTest(document=document), patch("dos_re_harness.cli.subprocess.run") as run:
                self.document = document
                with self.assertRaises((ValueError, OSError)):
                    self.run_plan()
                run.assert_not_called()

    def test_launch_failure_preserves_plan_and_input_identity(self):
        with patch("dos_re_harness.cli.subprocess.run", side_effect=FileNotFoundError("missing adapter")), \
                patch("dos_re_harness.evidence.git_commit", return_value="fixture"), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_plan(), 2)
        manifest = json.loads((self.root / "output/harness_manifest.json").read_text())
        self.assertEqual(manifest["input_observation"], "before_execution")
        self.assertEqual(manifest["execution"]["status"], "failed")
        self.assertIn("missing adapter", manifest["execution"]["error"])
        self.assertEqual(manifest["contracts"]["capture_plan"]["sha256"],
                         hashlib.sha256(self.plan.read_bytes()).hexdigest())
        self.assertEqual(manifest["capture_plan"]["project"], str(self.root / "project/project.json"))
        self.assertGreaterEqual(manifest["execution"]["wall_seconds"], 0)

    def test_existing_evidence_directory_is_rejected(self):
        output = self.root / "output"
        output.mkdir()
        (output / "old.bin").write_bytes(b"retained")
        with patch("dos_re_harness.cli.subprocess.run") as run:
            with self.assertRaisesRegex(ValueError, "fresh or empty"):
                self.run_plan()
            run.assert_not_called()
        self.assertEqual((output / "old.bin").read_bytes(), b"retained")

    def test_plan_resolves_movie_and_script_and_preserves_adapter_values(self):
        project_path = self.root / "project/project.json"
        project = json.loads(project_path.read_text())
        project["capture_adapter"]["configuration"] = {"delay": 0}
        project["capture_adapter"]["command"] = ["capture", "{startup_actions}", "{input_script}", "{delay}"]
        project_path.write_text(json.dumps(project), encoding="utf-8")
        (self.root / "input.script").write_text("fixture", encoding="utf-8")
        self.document.update({"movie": "project/movies/boot.movie.json", "input_script": "input.script",
                              "adapter_arguments": {"delay": 2.5}})
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(self.run_plan("--dry-run"), 0)
        command = json.loads(output.getvalue())
        self.assertEqual(command[-2:], [str(self.root / "input.script"), "2.5"])
        self.assertNotEqual(command[1], "")

    def test_real_synthetic_adapter_completes_and_records_manifest(self):
        project_path = self.root / "project/project.json"
        project = json.loads(project_path.read_text())
        project["capture_adapter"]["command"] = [sys.executable, "-c", "pass"]
        project_path.write_text(json.dumps(project), encoding="utf-8")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(self.run_plan(), 0)
        manifest = json.loads((self.root / "output/harness_manifest.json").read_text())
        self.assertEqual(manifest["execution"]["status"], "completed")
        self.assertEqual(manifest["exit_code"], 0)
        self.assertTrue(manifest["harness"]["sources"])


if __name__ == "__main__":
    unittest.main()
