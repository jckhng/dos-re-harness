from pathlib import Path
import contextlib
import hashlib
import io
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from dos_re_harness import audit
from dos_re_harness.cli import build_parser
from dos_re_harness.execution import load_run_plan, run_command


class ConsolidationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_environment_removal_is_child_only(self):
        with patch.dict(os.environ, {"DOS_RE_INHERITED_TEST": "present"}):
            result = run_command([sys.executable, "-B", "-c",
                'import os;assert "DOS_RE_INHERITED_TEST" not in os.environ'],
                cwd=self.root, out_dir=self.root / "run",
                unset_environment=["DOS_RE_INHERITED_TEST"])
            self.assertEqual(result["exit_code"], 0)
            self.assertEqual(result["unset_environment"], ["DOS_RE_INHERITED_TEST"])
            self.assertEqual(os.environ["DOS_RE_INHERITED_TEST"], "present")

    def test_invalid_environment_is_rejected_before_execution(self):
        for options in [dict(environment=[]), dict(unset_environment="VAR"),
                        dict(environment={"VAR": "x"}, unset_environment=["VAR"]),
                        dict(unset_environment=["BAD=NAME"])]:
            with self.subTest(options=options), self.assertRaises(ValueError):
                run_command([sys.executable, "-V"], cwd=self.root, out_dir=self.root / "out", **options)
        self.assertFalse((self.root / "out").exists())

    def test_invalid_jobs_do_not_launch_or_write_output(self):
        path = self.root / "jobs.json"
        for changes in [dict(command=["python", "${typo}"]), dict(input_groups=["missing"]),
                        dict(expected_exit_code=True), dict(expected_stdout="not a list")]:
            with self.subTest(changes=changes):
                job = dict(command=[sys.executable, "-V"])
                job.update(changes)
                path.write_text(json.dumps(dict(format_version=2, jobs={"test": job})))
                with self.assertRaises(ValueError):
                    load_run_plan(path, job="test")

    def test_expected_failure_cannot_hide_stale_input_or_wrong_output(self):
        path = self.root / "jobs.json"
        (self.root / "input").write_bytes(b"changed")
        job = dict(command=[sys.executable, "-c", "print('wrong');raise SystemExit(8)"],
                   expected_exit_code=8, expected_stdout=["required"],
                   inputs=[dict(path="input", sha256=hashlib.sha256(b"original").hexdigest())])
        path.write_text(json.dumps(dict(format_version=2, jobs={"negative": job})))
        for name, stale in [("stale", True), ("mismatch", False)]:
            if not stale:
                (self.root / "input").write_bytes(b"original")
            args = build_parser().parse_args(["run-plan", str(path), "--job", "negative",
                                             "--out-dir", str(self.root / name)])
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(args.func(args), 1)
            receipt = json.loads((self.root / name / "receipt.json").read_text())
            self.assertEqual(receipt["status"], "preflight_failed" if stale else "failed")

    def test_conflicting_shared_bindings_reject(self):
        path = self.root / "jobs.json"
        path.write_text(json.dumps(dict(format_version=2,
            input_groups={"a": [dict(path="input", sha256="0" * 64)],
                          "b": [dict(path="input", sha256="1" * 64)]},
            jobs={"test": dict(command=["python"], input_groups=["a", "b"])})))
        with self.assertRaisesRegex(ValueError, "conflicting"):
            load_run_plan(path, job="test")

    def test_v1_preserves_literal_arguments(self):
        path = self.root / "plan.json"
        path.write_text(json.dumps(dict(format_version=1, command=["python", "${literal}"])))
        self.assertEqual(load_run_plan(path)["command"], ["python", "${literal}"])

    def test_named_job_relocates_and_preserves_expected_failure(self):
        for name in ["first checkout", "second checkout"]:
            with self.subTest(name=name):
                root = self.root / name
                (root / ".work").mkdir(parents=True)
                (root / "input").write_bytes(b"oracle")
                binding = {"path": "input", "sha256": hashlib.sha256(b"oracle").hexdigest()}
                plan = root / "jobs.json"
                plan.write_text(json.dumps({"format_version": 2,
                    "input_groups": {"oracle": [binding], "unrelated": [
                        {"path": "unused", "sha256": "0" * 64}]},
                    "jobs": {"negative": {"command": ["native-python", "-c",
                        'import os,sys;assert "DOS_RE_INHERITED_TEST" not in os.environ;print(sys.argv[1]);sys.exit(8)',
                        "${message}"], "input_groups": ["oracle"],
                        "unset_environment": ["DOS_RE_INHERITED_TEST"],
                        "expected_exit_code": 8, "expected_stdout": ["controlled rejection"],
                        "dependencies_complete": True}}}))
                profile = root / ".work/host.json"
                profile.write_text(json.dumps({"format_version": 1,
                    "tools": {"native-python": [sys.executable, "-B"]},
                    "values": {"message": "controlled rejection"},
                    "environment": {"DOS_RE_INHERITED_TEST": "from-profile"}}))
                args = build_parser().parse_args(["run-plan", str(plan), "--job", "negative",
                    "--host-profile", str(profile), "--out-dir", str(root / ".work/run")])
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(args.func(args), 0)
                receipt = json.loads((root / ".work/run/receipt.json").read_text())
                outcome = json.loads((root / ".work/run/job-result.json").read_text())
                self.assertEqual(receipt["status"], "failed")
                self.assertEqual(receipt["exit_code"], 8)
                self.assertFalse(receipt["cache_eligible"])
                self.assertTrue(outcome["expectations_met"])
                paths = [row["path"] for row in receipt["inputs_before"]]
                self.assertIn(str(profile.resolve()), paths)
                self.assertNotIn(str((root / "unused").resolve()), paths)

    def test_full_text_workspace_path_is_rejected(self):
        (self.root / "guide.md").write_text("x" * 9000 + "\n" + self.root.as_posix())
        self.assertTrue(any("workspace path" in item for item in audit.audit_public_tree(self.root)))

    def test_local_config_is_rejected_even_without_personal_paths(self):
        (self.root / "settings.local.json").write_text('{}')
        self.assertTrue(any("local configuration" in item for item in audit.audit_public_tree(self.root)))

    def test_absolute_host_configuration_and_utf16_workspace_are_rejected(self):
        (self.root / "plan.json").write_text(json.dumps(dict(cwd="/opt/private/toolchain")))
        (self.root / "wide.txt").write_text(str(self.root), encoding="utf-16")
        errors = audit.audit_public_tree(self.root)
        self.assertTrue(any("host configuration" in item for item in errors))
        self.assertTrue(any("wide.txt" in item and "workspace path" in item for item in errors))

    def test_explicit_publication_list_does_not_walk_other_projects(self):
        (self.root / "public.txt").write_text("public")
        (self.root / "private.exe").write_bytes(b"MZ")
        self.assertEqual(audit.audit_paths(self.root, ["public.txt"]), [])
        with self.assertRaises(ValueError):
            audit.audit_paths(self.root, ["../outside"])

    def test_runner_scopes_child_environment_and_preserves_parent(self):
        root = Path(__file__).resolve().parents[1]
        spec = importlib.util.spec_from_file_location("harness_test_runner", root / "scripts/run_tests.py")
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        before, cwd = dict(os.environ), Path.cwd()
        scratch = self.root / "temp with spaces"
        with patch.object(runner.subprocess, "run", return_value=subprocess.CompletedProcess([], 7)) as child:
            self.assertEqual(runner.main(["--temp-root", str(scratch), "--pattern", "test_execution.py"]), 7)
        self.assertEqual(os.environ, before)
        self.assertEqual(Path.cwd(), cwd)
        self.assertEqual(child.call_args.kwargs["env"]["TEMP"], str(scratch.resolve()))
        self.assertEqual(child.call_args.kwargs["cwd"], root)
        self.assertEqual(list(scratch.iterdir()), [])


@unittest.skipUnless(shutil.which("git"), "Git required for index publication checks")
class StagedPublicationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.git("init", "-q")

    def git(self, *args):
        env = dict(os.environ)
        for name in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY"]:
            env.pop(name, None)
        env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
        return subprocess.run(["git", "-C", str(self.root), "-c", "core.autocrlf=false", *args],
            env=env, check=True, capture_output=True)

    def test_staged_bytes_are_checked_instead_of_working_copy(self):
        path = self.root / "settings.json"
        path.write_text(json.dumps({"cwd": str(self.root)}))
        self.git("add", "settings.json")
        path.write_text('{"cwd":"."}')
        self.assertTrue(audit.audit_staged_tree(self.root))
        self.git("add", "settings.json")
        path.write_text(json.dumps({"cwd": str(self.root)}))
        self.assertEqual(audit.audit_staged_tree(self.root), [])

    def test_force_added_private_files_are_not_silently_ignored(self):
        (self.root / ".work").mkdir()
        (self.root / ".work/host.json").write_text('{}')
        self.git("add", "-f", ".work/host.json")
        self.assertTrue(any("private/generated" in item for item in audit.audit_staged_tree(self.root)))
