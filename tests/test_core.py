from __future__ import annotations

import json
import hashlib
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path


TOOLKIT_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_ROOT = TOOLKIT_ROOT / "tests" / "fixtures" / "minimal-project"
sys.path.insert(0, str(TOOLKIT_ROOT / "src"))

from dos_re_harness.project import load_project, validate_project
from dos_re_harness.audit import audit_public_tree
from dos_re_harness.backend import diagnose, validate_capabilities
from dos_re_harness.evidence import write_evidence_manifest
from dos_re_harness.frames import compare_raw_frames
from dos_re_harness.movie import scenario_actions
from dos_re_harness.schema import load_schema, parse_dump
from dos_re_harness.screens import ScreenClassifier
from dos_re_harness.state import diff_states
from dos_re_harness.traces import (
    MISSING_TRACE_VALUE,
    first_trace_difference,
    load_jsonl,
)


class SchemaTests(unittest.TestCase):
    def test_flat_and_repeated_fields_decode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            schema_path = Path(temporary) / "state.json"
            schema_path.write_text(
                json.dumps(
                    {
                        "fields": [
                            {"name": "counter", "offset": "0x00", "type": "u16le"}
                        ],
                        "blocks": [
                            {
                                "instances": [
                                    {"name": "a", "base": "0x04"},
                                    {"name": "b", "base": "0x08"},
                                ],
                                "fields": [
                                    {
                                        "name": "slot_{instance}_value",
                                        "offset": 0,
                                        "type": "s32le",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            fields = load_schema(schema_path)
            data = bytearray(12)
            struct.pack_into("<H", data, 0, 513)
            struct.pack_into("<i", data, 4, -7)
            struct.pack_into("<i", data, 8, 9001)
            self.assertEqual(
                parse_dump(bytes(data), fields),
                {"counter": 513, "slot_a_value": -7, "slot_b_value": 9001},
            )

    def test_state_diff_strictness(self) -> None:
        fields = load_schema(FIXTURE_ROOT / "state.schema.json")
        differences, matches, skipped = diff_states(
            {"score": 1}, {"score": 2}, fields, strict=False
        )
        self.assertEqual((matches, skipped), (0, len(fields) - 1))
        self.assertEqual(differences[0][0].name, "score")


class ScreenTests(unittest.TestCase):
    def test_ordered_region_hash_and_metric_classification(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            raw = bytes([0, 1, 2, 3] * 4)
            top_row = raw[:4]
            path = Path(temporary) / "screens.json"
            path.write_text(
                json.dumps(
                    {
                        "width": 4,
                        "height": 4,
                        "states": [
                            {
                                "name": "exact",
                                "region": [0, 0, 4, 1],
                                "crc32": hex(zlib.crc32(top_row)),
                            },
                            {
                                "name": "fallback",
                                "region": [0, 0, 4, 4],
                                "unique_min": 4,
                            },
                        ],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(ScreenClassifier.load(path).classify(raw), "exact")


class WorkflowTests(unittest.TestCase):
    def test_public_tree_audit_rejects_binary_and_personal_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "GAME.EXE").write_bytes(b"MZ")
            (root / "notes.txt").write_text(
                "C:\\" + r"Users\developer\private", encoding="utf-8"
            )
            errors = audit_public_tree(root)
            self.assertTrue(
                any("forbidden publication file type" in item for item in errors)
            )
            self.assertTrue(any("absolute user-home path" in item for item in errors))

    def test_harness_passes_public_tree_audit(self) -> None:
        self.assertEqual(audit_public_tree(TOOLKIT_ROOT), [])

    def test_input_movie_resolves_relative_to_project(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            movie = root / "movies" / "entry.json"
            movie.parent.mkdir()
            movie.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "actions": ["waitvga:title:12", "hold:spc:1.0"],
                    }
                ),
                encoding="utf-8",
            )
            self.assertEqual(
                scenario_actions(root, {"input_movie": "movies/entry.json"}),
                ["waitvga:title:12", "hold:spc:1.0"],
            )

    def test_input_movie_and_inline_actions_are_mutually_exclusive(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot define both"):
            scenario_actions(
                Path("."),
                {
                    "input_movie": "entry.json",
                    "startup_actions": ["hold:spc:1.0"],
                },
            )

    def test_raw_frame_difference_reports_exact_bounds(self) -> None:
        result, deltas = compare_raw_frames(
            bytes([0, 1, 2, 3, 4, 5]),
            bytes([0, 9, 2, 3, 8, 5]),
            width=3,
            height=2,
        )
        self.assertEqual(result["diff_pixels"], 2)
        self.assertEqual(result["bbox"], [1, 0, 2, 2])
        self.assertEqual(result["max_index_delta"], 8)
        self.assertEqual(deltas, bytes([0, 8, 0, 0, 4, 0]))

    def test_raw_frame_difference_rejects_invalid_dimensions(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be positive"):
            compare_raw_frames(b"", b"", width=0, height=1)

    def test_trace_comparison_stops_at_first_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            trace_path = Path(temporary) / "trace.jsonl"
            trace_path.write_text(
                '{"tick": 0, "x": 4}\n{"tick": 1, "x": 5}\n',
                encoding="utf-8",
            )
            original = load_jsonl(trace_path)
            difference = first_trace_difference(
                original,
                [{"tick": 0, "x": 4}, {"tick": 1, "x": 6}],
            )
            self.assertEqual(difference, (1, {"x": (5, 6)}))

    def test_trace_literal_missing_marker_is_not_a_missing_field(self) -> None:
        self.assertEqual(
            first_trace_difference([{"x": "<missing>"}], [{}]),
            (0, {"x": ("<missing>", MISSING_TRACE_VALUE)}),
        )


class HarnessContractTests(unittest.TestCase):
    def test_project_validates(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        self.assertEqual(validate_project(project), [])
        self.assertEqual(validate_capabilities(project), [])

    def test_doctor_has_stable_core_checks(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        names = {diagnostic.name for diagnostic in diagnose(project)}
        self.assertTrue({"host", "python", "capture-command"} <= names)

    def test_generic_launcher_has_no_target_defaults(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertNotIn('string]$Program = "', launcher)
        self.assertNotIn('string]$MountDir = "', launcher)
        self.assertNotIn('string]$StateSchema = "', launcher)
        self.assertIn("[uint32]$VgaAddress", launcher)
        self.assertIn("[int]$VgaWidth", launcher)
        self.assertIn("[int]$VgaHeight", launcher)
        self.assertIn("& wsl.exe --exec bash", launcher)

    def test_generic_launcher_preserves_empty_program_arguments(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('$programArgumentsArg = if ($ProgramArguments.Length -gt 0)', launcher)
        self.assertIn('$ProgramArguments\n    } else {\n        "__none__"', launcher)
        self.assertIn('if [ "$program_arguments" = "__none__" ]; then', launcher)
        self.assertIn("$programArgumentsArg $VgaAddress $VgaWidth $VgaHeight", launcher)

    def test_backend_lock_matches_patch(self) -> None:
        backend = TOOLKIT_ROOT / "backends" / "dosbox-x-remotedebug"
        lock = json.loads(
            (backend / "backend.lock.json").read_text(encoding="utf-8")
        )
        digest = hashlib.sha256(
            (backend / lock["patch"]["path"]).read_bytes()
        ).hexdigest()
        self.assertEqual(digest, lock["patch"]["sha256"])

    def test_remote_controller_imports_without_target_modules(self) -> None:
        from dos_re_harness import remote_capture

        self.assertTrue(callable(remote_capture.main))

    def test_evidence_manifest_hashes_capture_artifacts(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        with tempfile.TemporaryDirectory() as temporary:
            out_dir = Path(temporary)
            specimen = out_dir / "specimen"
            specimen.mkdir()
            project.data["specimen"] = {
                "root": str(specimen),
                "mutable_files": ["SAVE.DAT"],
            }
            project.data["capture_adapter"]["backend_lock"] = str(
                TOOLKIT_ROOT
                / "backends"
                / "dosbox-x-remotedebug"
                / "backend.lock.json"
            )
            project.data["capture_adapter"]["configuration"] = {
                "machine": "synthetic"
            }
            (out_dir / "remote_runtime_ds.bin").write_bytes(b"state")
            manifest_path = write_evidence_manifest(
                project,
                "boot",
                out_dir,
                ["capture", "boot"],
                0,
            )
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(document["project"]["id"], "minimal-fixture")
            self.assertEqual(document["exit_code"], 0)
            self.assertEqual(
                document["artifacts"][0]["path"], "remote_runtime_ds.bin"
            )
            self.assertEqual(
                Path(document["contracts"]["input_movie"]["path"]).name,
                "boot.movie.json",
            )
            self.assertEqual(
                document["backend"]["upstream"]["commit"],
                "2917cb31e00a9d0a935060ac9186c1a7885da0fd",
            )
            self.assertEqual(
                document["backend"]["patch"]["sha256"],
                "09d05e31ca4e1645dee91b8bf081d6b43db5cefaffbb318d08fe2a93dd4a1e6e",
            )
            self.assertEqual(
                document["capture"]["configuration"]["machine"],
                "synthetic",
            )
            self.assertEqual(document["capture"]["selection"]["dump_segment"], "ds")
            self.assertEqual(
                document["capture"]["mutable_baseline"],
                [{"path": "SAVE.DAT", "present": False}],
            )


if __name__ == "__main__":
    unittest.main()
