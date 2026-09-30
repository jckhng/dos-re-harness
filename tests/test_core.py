from __future__ import annotations

import json
import base64
import gzip
import hashlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zlib
import wave
import zlib
from pathlib import Path
from unittest.mock import patch


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
    compare_jsonl,
    first_trace_difference,
    load_jsonl,
)


class CaptureAdapterTests(unittest.TestCase):
    def test_wsl_runtime_script_normalizes_windows_newlines(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        normalization = '$bash = $bash.Replace("`r`n", "`n").Replace("`r", "`n")'
        write = "[System.IO.File]::WriteAllText($tempScript, $bash, $utf8NoBom)"
        self.assertIn(normalization, launcher)
        self.assertLess(launcher.index(normalization), launcher.index(write))

    def test_powershell_launcher_forwards_positionals_out_and_help(self) -> None:
        powershell = shutil.which("pwsh")
        if powershell is None:
            self.skipTest("PowerShell Core is unavailable")
        launcher = TOOLKIT_ROOT / "scripts" / "dos-re.ps1"
        validate = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-File",
                str(launcher),
                "validate-project",
                str(FIXTURE_ROOT / "project.json"),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(validate.returncode, 0, validate.stderr)
        self.assertIn("VALID project=minimal-fixture", validate.stdout)
        help_result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-File",
                str(launcher),
                "plan-state-tail",
                "--help",
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr)
        self.assertIn("usage: cli.py plan-state-tail", help_result.stdout)
        with tempfile.TemporaryDirectory() as temporary:
            dump = Path(temporary) / "state.bin"
            output = Path(temporary) / "state.json"
            dump.write_bytes(bytes(8))
            parse = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-File",
                    str(launcher),
                    "parse-state",
                    "--schema",
                    str(FIXTURE_ROOT / "state.schema.json"),
                    "--dump",
                    str(dump),
                    "--out",
                    str(output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(parse.returncode, 0, parse.stderr)
            self.assertTrue(output.is_file())
            capture = Path(temporary) / "capture"
            for hit in (2, 7):
                checkpoint = capture / "checkpoints" / f"breakpoint_hit-{hit}"
                checkpoint.mkdir(parents=True)
                (checkpoint / "memory.bin").write_bytes(bytes(range(8)))
            (capture / "capture_summary.json").write_text(
                json.dumps(
                    {
                        "break_state": {
                            "post_resume_breakpoint_series": {"hits": [2, 7]}
                        }
                    }
                ),
                encoding="utf-8",
            )
            checkpoint_output = Path(temporary) / "checkpoint-index.json"
            checkpoint_index = subprocess.run(
                [
                    powershell,
                    "-NoProfile",
                    "-File",
                    str(launcher),
                    "index-checkpoints",
                    str(capture),
                    "--artifact",
                    "memory.bin",
                    "--expected-hits",
                    "2,7",
                    "--out",
                    str(checkpoint_output),
                ],
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertEqual(
                checkpoint_index.returncode, 0, checkpoint_index.stderr
            )
            self.assertEqual(
                json.loads(checkpoint_output.read_text(encoding="utf-8"))["hits"],
                [2, 7],
            )

    def test_state_tail_plan_finds_first_input_state_change(self) -> None:
        from dos_re_harness.state_tail import build_state_tail_plan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            previous = root / "previous.input.script"
            current = root / "current.input.script"
            previous.write_text(
                "dos-re-state-input-script-v1\n"
                "# state_field=loop_tick\n"
                "# terminal_value=12\n"
                "1=down.left\n"
                "5=up.left\n"
                "10=down.right\n"
                "12=up.right\n",
                encoding="utf-8",
            )
            current.write_text(
                "dos-re-state-input-script-v1\n"
                "# state_field=loop_tick\n"
                "# terminal_value=12\n"
                "1=down.left\n"
                "5=up.left\n"
                "7=down.right\n"
                "12=up.right\n",
                encoding="utf-8",
            )
            snapshot = root / "checkpoints" / "loop_tick-5"
            snapshot.mkdir(parents=True)
            (snapshot / "remote_runtime_ds.bin").write_bytes(bytes(65536))
            (snapshot / "remote_runtime_registers.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            movie = root / "resume.movie.json"
            movie.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "actions": [
                            "breakstate:0x850c:loop_tick==1:63",
                            "clearbreak:0x850c",
                        ],
                    }
                ),
                encoding="utf-8",
            )

            plan = build_state_tail_plan(
                previous_script=previous,
                current_script=current,
                snapshot=snapshot,
                checkpoint_value=5,
                end_value=11,
                breakpoint="0x850c",
                state_field="loop_tick",
                maximum_hit_margin=62,
                resume_next_linear="0x850f",
                bootstrap_movie=movie,
                capture_out=root / "capture",
                transition_breakpoint="0x0824:0x6f52",
                transition_out=root / "transition",
            )

        self.assertEqual(plan["first_changed_value"], 7)
        self.assertEqual(plan["capture"]["first_value"], 5)
        self.assertEqual(plan["capture"]["last_value"], 11)
        self.assertEqual(plan["capture"]["value_count"], 7)
        self.assertEqual(
            plan["capture"]["stop_boundary"],
            {
                "value": 11,
                "input_transitions": [],
                "transition_count": 0,
                "requires_explicit_input_phase": False,
                "nearest_transition_free_before": 11,
                "nearest_transition_free_after": 11,
            },
        )
        self.assertIn(
            "resume_checkpoint_script=checkpointstatescriptfile:"
            "0x850c:loop_tick:"
            "5+6+7+8+9+10+11:68",
            plan["capture"]["adapter_arguments"],
        )
        self.assertEqual(
            plan["transition"]["breakpoint"],
            "0x0824:0x6f52",
        )

    def test_state_tail_plan_flags_stop_on_input_transition(self) -> None:
        from dos_re_harness.state_tail import state_input_boundary

        events = [
            (9, True, ["left"]),
            (10, False, ["left"]),
            (10, True, ["right"]),
            (11, False, ["right"]),
        ]

        boundary = state_input_boundary(events, 10)

        self.assertEqual(boundary["transition_count"], 2)
        self.assertTrue(boundary["requires_explicit_input_phase"])
        self.assertEqual(boundary["nearest_transition_free_before"], 8)
        self.assertEqual(boundary["nearest_transition_free_after"], 12)
        self.assertEqual(
            boundary["input_transitions"],
            [
                {"pressed": False, "qcodes": ["left"]},
                {"pressed": True, "qcodes": ["right"]},
            ],
        )

    def test_state_input_slice_reconstructs_held_keys(self) -> None:
        from dos_re_harness.remote_capture import load_state_input_script
        from dos_re_harness.state_tail import slice_state_input_script

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "route.input.script"
            output = root / "tail.input.script"
            manifest = root / "tail.json"
            source.write_text(
                "dos-re-state-input-script-v1\n"
                "# state_field=loop_tick\n"
                "1=down.left\n"
                "3=down.spc\n"
                "5=up.left\n"
                "5=down.right\n"
                "7=up.right\n"
                "9=up.spc\n",
                encoding="utf-8",
            )

            report = slice_state_input_script(
                source,
                output,
                resume_value=5,
                manifest=manifest,
            )
            metadata, events = load_state_input_script(output)

            self.assertNotIn(
                str(source),
                manifest.read_text(encoding="utf-8"),
            )

        self.assertEqual(report["initial_held_qcodes"], ["left", "spc"])
        self.assertEqual(report["event_count"], 4)
        self.assertEqual(metadata["resume_value"], "5")
        self.assertEqual(metadata["first_hook_value"], "6")
        self.assertEqual(metadata["initial_held_qcodes"], "left+spc")
        self.assertEqual(metadata["preapplied_through"], "5")
        self.assertEqual(events[0], (5, False, ["left"]))
        self.assertEqual(events[1], (5, True, ["right"]))

    def test_state_tail_plan_rejects_invalid_snapshot_and_bootstrap(self) -> None:
        from dos_re_harness.state_tail import build_state_tail_plan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "route.input.script"
            script.write_text(
                "dos-re-state-input-script-v1\n"
                "# state_field=loop_tick\n"
                "1=down.left\n"
                "2=up.left\n",
                encoding="utf-8",
            )
            snapshot = root / "loop_tick-1"
            snapshot.mkdir()
            (snapshot / "remote_runtime_ds.bin").write_bytes(b"short")
            (snapshot / "remote_runtime_registers.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            movie = root / "resume.movie.json"
            movie.write_text(
                json.dumps({"format_version": 1, "actions": ["wait:1"]}),
                encoding="utf-8",
            )

            with self.assertRaisesRegex(ValueError, "expected 65536 bytes"):
                build_state_tail_plan(
                    previous_script=script,
                    current_script=script,
                    snapshot=snapshot,
                    checkpoint_value=1,
                    end_value=2,
                    breakpoint="0x850c",
                    state_field="loop_tick",
                    bootstrap_movie=movie,
                    capture_out=root / "capture",
                )

    def test_adapter_arguments_merge_configuration_scenario_and_cli(self) -> None:
        from dos_re_harness.cli import capture_adapter_replacements

        adapter = {
            "configuration": {
                "poke_file": "",
                "restore_registers": "",
                "resume_checkpoint_script": "",
            }
        }
        scenario = {
            "arguments": {
                "resume_checkpoint_script": "scenario-action",
                "delay_seconds": 8,
            }
        }
        self.assertEqual(
            capture_adapter_replacements(
                adapter,
                scenario,
                [
                    "poke_file=ds:0:C:\\snapshot\\remote_runtime_ds.bin",
                    "resume_checkpoint_script=resume-action",
                ],
            ),
            {
                "poke_file": "ds:0:C:\\snapshot\\remote_runtime_ds.bin",
                "restore_registers": "",
                "resume_checkpoint_script": "resume-action",
                "delay_seconds": "8",
            },
        )
        with self.assertRaisesRegex(ValueError, "unknown capture adapter"):
            capture_adapter_replacements(
                adapter,
                scenario,
                ["unconfigured=value"],
            )

    def test_capture_summary_parser_defaults_to_one_line_output(self) -> None:
        from dos_re_harness.cli import build_parser

        args = build_parser().parse_args(
            ["summarize-capture", "capture-directory"]
        )
        self.assertEqual(args.capture_dir, Path("capture-directory"))
        self.assertFalse(args.json)
        self.assertIsNone(args.out)

    def test_state_tail_planner_parser_exposes_preflight_inputs(self) -> None:
        from dos_re_harness.cli import build_parser

        args = build_parser().parse_args(
            [
                "plan-state-tail",
                "project.json",
                "probe",
                "--previous-input-script",
                "v1.input.script",
                "--input-script",
                "v2.input.script",
                "--resume-from",
                "loop_tick-40",
                "--checkpoint-value",
                "40",
                "--end-value",
                "90",
                "--state-field",
                "loop_tick",
                "--breakpoint",
                "0x850c",
                "--movie",
                "resume.movie.json",
                "--capture-out",
                "capture",
                "--sliced-input-out",
                "tail.input.script",
                "--sliced-input-manifest",
                "tail.input.json",
                "--out",
                "plan.json",
            ]
        )
        self.assertEqual(args.checkpoint_value, 40)
        self.assertEqual(args.end_value, 90)
        self.assertEqual(args.maximum_hit_margin, 62)
        self.assertEqual(args.sliced_input_out, Path("tail.input.script"))
        self.assertEqual(args.sliced_input_manifest, Path("tail.input.json"))

    def test_state_tail_plan_uses_generated_input_slice(self) -> None:
        from dos_re_harness.cli import build_parser

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project_root = root / "project"
            shutil.copytree(FIXTURE_ROOT, project_root)
            project_path = project_root / "project.json"
            project = json.loads(project_path.read_text(encoding="utf-8"))
            project["capture_adapter"]["configuration"] = {
                "poke_file": "",
                "resume_checkpoint_script": "",
                "resume_next_linear": "",
                "checkpoint_vga": "1",
            }
            project_path.write_text(
                json.dumps(project),
                encoding="utf-8",
            )
            script = root / "route.input.script"
            script.write_text(
                "dos-re-state-input-script-v1\n"
                "# state_field=loop_tick\n"
                "1=down.left\n"
                "5=up.left\n"
                "7=down.right\n"
                "9=up.right\n",
                encoding="utf-8",
            )
            snapshot = root / "loop_tick-5"
            snapshot.mkdir()
            (snapshot / "remote_runtime_ds.bin").write_bytes(bytes(8))
            (snapshot / "remote_runtime_registers.json").write_text(
                "{}\n",
                encoding="utf-8",
            )
            movie = root / "resume.movie.json"
            movie.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "actions": [
                            "breakstate:0x850c:loop_tick==1:63",
                            "clearbreak:0x850c",
                        ],
                    }
                ),
                encoding="utf-8",
            )
            tail = root / "tail.input.script"
            tail_manifest = root / "tail.input.json"
            plan_path = root / "plan.json"
            args = build_parser().parse_args(
                [
                    "plan-state-tail",
                    str(project_path),
                    "boot",
                    "--previous-input-script",
                    str(script),
                    "--input-script",
                    str(script),
                    "--resume-from",
                    str(snapshot),
                    "--checkpoint-value",
                    "5",
                    "--end-value",
                    "8",
                    "--state-field",
                    "loop_tick",
                    "--breakpoint",
                    "0x850c",
                    "--movie",
                    str(movie),
                    "--capture-out",
                    str(root / "capture"),
                    "--sliced-input-out",
                    str(tail),
                    "--sliced-input-manifest",
                    str(tail_manifest),
                    "--dump-size",
                    "8",
                    "--out",
                    str(plan_path),
                ]
            )

            self.assertEqual(args.func(args), 0)
            plan = json.loads(plan_path.read_text(encoding="utf-8"))

            self.assertTrue(tail.is_file())
            self.assertTrue(tail_manifest.is_file())
            self.assertEqual(plan["scripts"]["capture_slice"]["resume_value"], 5)
            capture_args = plan["commands"]["capture_cli_args"]
            self.assertEqual(
                capture_args[capture_args.index("--input-script") + 1],
                str(tail.resolve()),
            )

    def test_audio_and_write_trace_commands_are_exposed(self) -> None:
        from dos_re_harness.cli import build_parser

        parser = build_parser()
        inspect = parser.parse_args(["inspect-wave", "capture.wav"])
        self.assertEqual(inspect.wave, Path("capture.wav"))
        compare = parser.parse_args(
            ["diff-wave", "original.wav", "rewrite.wav", "--mixdown"]
        )
        self.assertTrue(compare.mixdown)
        trace = parser.parse_args(
            [
                "extract-write-trace",
                "capture",
                "--address-register",
                "ebx",
                "--value-register",
                "ecx",
                "--out",
                "writes.json",
            ]
        )
        self.assertEqual(trace.address_register, "ebx")
        self.assertEqual(trace.value_register, "ecx")
        checkpoint_index = parser.parse_args(
            [
                "index-checkpoints",
                "capture",
                "--artifact",
                "remote_runtime_lowmem.bin",
                "--offset",
                "0x20",
                "--length",
                "320",
                "--register",
                "cs",
                "--expected-hits",
                "2,7",
                "--out",
                "index.json",
            ]
        )
        self.assertEqual(checkpoint_index.offset, 0x20)
        self.assertEqual(checkpoint_index.length, 320)
        self.assertEqual(checkpoint_index.register, ["cs"])
        self.assertEqual(checkpoint_index.expected_hits, [2, 7])
        contiguous_index = parser.parse_args(
            [
                "index-checkpoints",
                "capture",
                "--artifact",
                "memory.bin",
                "--expected-hit-count",
                "96",
                "--out",
                "index.json",
            ]
        )
        self.assertEqual(contiguous_index.expected_hit_count, 96)


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
    def test_halted_breakpoint_screenshot_runs_then_restores_instruction(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            capture_halted_breakpoint_screenshot,
        )

        class FakeGdb:
            def __init__(self) -> None:
                self.calls: list[tuple[object, ...]] = []

            def remove_breakpoint(self, address: int) -> None:
                self.calls.append(("remove_breakpoint", address))

            def read_memory(self, address: int, size: int) -> bytes:
                self.calls.append(("read_memory", address, size))
                if address == 0x27431:
                    return b"\xe0\x03"
                return b"\x40\x75"

            def write_memory(self, address: int, data: bytes) -> None:
                self.calls.append(("write_memory", address, data))

            def registers(self) -> dict[str, int]:
                self.calls.append(("registers",))
                return {"eip": 0xF71A, "eflags": 0x202}

            def write_registers(self, registers: dict[str, int]) -> None:
                self.calls.append(("write_registers", registers))

            def continue_nowait(self) -> None:
                self.calls.append(("continue_nowait",))

            def halt(self, timeout: float) -> None:
                self.calls.append(("halt", timeout))

            def insert_breakpoint(self, address: int) -> None:
                self.calls.append(("insert_breakpoint", address))

        class FakeQmp:
            def memdump(self, address: int, size: int) -> bytes:
                self.memdump_args = (address, size)
                return bytes(size)

        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "checkpoints" / "breakpoint_hit-1"
            checkpoint.mkdir(parents=True)
            metadata_path = checkpoint / "remote_runtime_registers.json"
            metadata_path.write_text("{}\n", encoding="utf-8")
            record: dict[str, object] = {"path": str(checkpoint)}
            gdb = FakeGdb()
            qmp = FakeQmp()
            with patch(
                "dos_re_harness.remote_capture.capture_optional_screenshot",
                return_value=None,
            ) as screenshot:
                capture_halted_breakpoint_screenshot(
                    gdb,
                    qmp,
                    10.0,
                    0x082474DA,
                    0xF71A,
                    0xB8000,
                    80 * 25 * 2,
                    record,
                    0.0,
                    preserve_memory=[(0x27431, 2)],
                )

            self.assertEqual(
                gdb.calls,
                [
                    ("remove_breakpoint", 0x082474DA),
                    ("read_memory", 0xF71A, 2),
                    ("read_memory", 0x27431, 2),
                    ("registers",),
                    ("write_memory", 0xF71A, b"\xeb\xfe"),
                    ("continue_nowait",),
                    ("halt", 10.0),
                    ("write_memory", 0x27431, b"\xe0\x03"),
                    ("write_memory", 0xF71A, b"\x40\x75"),
                    (
                        "write_registers",
                        {"eip": 0xF71A, "eflags": 0x202},
                    ),
                    ("insert_breakpoint", 0x082474DA),
                ],
            )
            self.assertEqual(qmp.memdump_args, (0xB8000, 80 * 25 * 2))
            screenshot.assert_called_once_with(
                qmp,
                checkpoint / "remote_runtime_screen.png",
            )
            self.assertTrue(record["screenshot_exact_checkpoint"])
            self.assertEqual(
                record["screenshot_preserved_memory"],
                [
                    {
                        "address": 0x27431,
                        "size": 2,
                        "sha256": hashlib.sha256(b"\xe0\x03").hexdigest(),
                    }
                ],
            )
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertTrue(metadata["screenshot_exact_checkpoint"])
            self.assertEqual(
                metadata["screenshot_poke"],
                {
                    "address": 0xF71A,
                    "bytes": "ebfe",
                    "restored": "4075",
                },
            )

    def test_configured_post_display_capture_is_checkpoint_mode_neutral(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            capture_configured_post_display,
        )

        record: dict[str, object] = {"path": "checkpoint"}
        with patch(
            "dos_re_harness.remote_capture.capture_post_display_screenshot"
        ) as capture:
            capture_configured_post_display(
                "gdb",
                "qmp",
                10.0,
                (0x0824, 0x03D1),
                (0x8611, b"\xeb\xfe"),
                record,
                0x850C,
                0.05,
                primary_breakpoint_installed=False,
            )
            capture.assert_called_once_with(
                "gdb",
                "qmp",
                10.0,
                (0x0824, 0x03D1),
                0x8611,
                b"\xeb\xfe",
                record,
                0.05,
                primary_breakpoint_installed=False,
            )
        self.assertEqual(record["primary_breakpoint"], 0x850C)

    def test_capture_parser_accepts_evidence_hashed_movie_override(self) -> None:
        from dos_re_harness.cli import build_parser

        args = build_parser().parse_args(
            [
                "capture",
                "project.json",
                "probe",
                "--out-dir",
                "capture",
                "--movie",
                "generated.movie.json",
                "--input-script",
                "generated.input.script",
            ]
        )
        self.assertEqual(args.movie, Path("generated.movie.json"))
        self.assertEqual(args.input_script, Path("generated.input.script"))

    def test_screen_wait_action_accepts_reusable_poll_interval(self) -> None:
        from dos_re_harness.remote_capture import parse_screen_wait_action

        self.assertEqual(
            parse_screen_wait_action(
                "waitvga:gameplay-cockpit-loaded:15:0.01",
                "waitvga",
            ),
            ("gameplay-cockpit-loaded", 15.0, 0.01),
        )
        self.assertEqual(
            parse_screen_wait_action(
                "waitnotvga:transition:3",
                "waitnotvga",
            ),
            ("transition", 3.0, 0.5),
        )
        with self.assertRaises(ValueError):
            parse_screen_wait_action("waitvga:state:2:0", "waitvga")

    def test_runfor_action_requires_positive_bounded_duration(self) -> None:
        from dos_re_harness.remote_capture import parse_run_for_action

        self.assertEqual(parse_run_for_action("runfor:1.25"), 1.25)
        with self.assertRaises(ValueError):
            parse_run_for_action("runfor:0")
        with self.assertRaises(ValueError):
            parse_run_for_action("run:1")

    def test_runtap_action_requires_key_and_positive_hold_duration(self) -> None:
        from dos_re_harness.remote_capture import parse_run_tap_action

        self.assertEqual(parse_run_tap_action("runtap:f1"), ("f1", 0.2))
        self.assertEqual(
            parse_run_tap_action("runtap:spc:0.75"),
            ("spc", 0.75),
        )
        with self.assertRaises(ValueError):
            parse_run_tap_action("runtap:")
        with self.assertRaises(ValueError):
            parse_run_tap_action("runtap:f1:0")
        with self.assertRaises(ValueError):
            parse_run_tap_action("tap:f1:0.2")

    def test_rununtilstop_action_requires_positive_timeout(self) -> None:
        from dos_re_harness.remote_capture import parse_run_until_stop_action

        self.assertEqual(
            parse_run_until_stop_action("rununtilstop:12.5"),
            12.5,
        )
        with self.assertRaises(ValueError):
            parse_run_until_stop_action("rununtilstop:0")
        with self.assertRaises(ValueError):
            parse_run_until_stop_action("runfor:1")

    def test_rsp_linear_breakpoint_uses_gdb_software_packet(self) -> None:
        from dos_re_harness.remote_capture import RspClient

        client = RspClient.__new__(RspClient)
        packets = []
        client.packet = lambda payload: packets.append(payload) or "OK"
        client.insert_breakpoint(0x4A05C)
        self.assertEqual(packets, ["Z0,4a05c,1"])

    def test_rsp_segmented_breakpoint_packs_backend_address(self) -> None:
        from dos_re_harness.remote_capture import (
            parse_segmented_address,
            parse_segmented_breakpoint_series_action,
            RspClient,
            parse_segmented_nth_breakpoint_action,
            pack_segment_offset,
        )

        self.assertEqual(pack_segment_offset(0x0824, 0x01A5), 0x082401A5)
        self.assertEqual(
            parse_segmented_address("0824:03d1"),
            (0x0824, 0x03D1),
        )
        self.assertEqual(
            parse_segmented_nth_breakpoint_action(
                "breaksonth:0824:b39e:14"
            ),
            (0x0824B39E, 14),
        )
        with self.assertRaises(ValueError):
            parse_segmented_nth_breakpoint_action(
                "breaksonth:0x0824:0xb39e:0"
            )
        self.assertEqual(
            parse_segmented_breakpoint_series_action(
                "breakseries:0x0824:0xb39e:2+9+17"
            ),
            (0x0824, 0xB39E, [2, 9, 17]),
        )
        for invalid in (
            "breakseries:0x0824:0xb39e:",
            "breakseries:0x0824:0xb39e:2+2",
            "breakseries:0x0824:0xb39e:9+2",
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    parse_segmented_breakpoint_series_action(invalid)
        with self.assertRaises(ValueError):
            pack_segment_offset(0x10000, 0)
        client = RspClient.__new__(RspClient)
        packets = []
        client.packet = lambda payload: packets.append(payload) or "OK"
        client.insert_breakpoint(pack_segment_offset(0x0824, 0x01A5))
        self.assertEqual(packets, ["Z0,82401a5,1"])

    def test_rsp_reads_only_requested_segment_state_fields(self) -> None:
        from dos_re_harness.remote_capture import (
            RspClient,
            read_segment_state,
        )
        from dos_re_harness.schema import Field

        packets = []
        client = RspClient.__new__(RspClient)

        def packet(payload: str) -> str:
            packets.append(payload)
            return {
                "m112c8,2": "2a00",
                "m112ca,2": "f6ff",
            }[payload]

        client.packet = packet
        fields = [
            Field("loop_tick", 0x12C8, 2, "u16le"),
            Field("armor", 0x12CA, 2, "s16le"),
        ]
        self.assertEqual(
            read_segment_state(client, 0x1000, fields),
            {"loop_tick": 42, "armor": -10},
        )
        self.assertEqual(packets, ["m112c8,2", "m112ca,2"])

    def test_rsp_chunked_memory_read_preserves_requested_range(self) -> None:
        from dos_re_harness.remote_capture import RspClient

        packets = []
        client = RspClient.__new__(RspClient)

        def packet(payload: str) -> str:
            packets.append(payload)
            return {
                "m1000,4": "00010203",
                "m1004,2": "0405",
            }[payload]

        client.packet = packet
        self.assertEqual(
            client.read_memory_chunked(0x1000, 6, chunk_size=4),
            bytes(range(6)),
        )
        self.assertEqual(packets, ["m1000,4", "m1004,2"])

    def test_breakpoint_stack_snapshot_records_near_return_address(self) -> None:
        from dos_re_harness.remote_capture import breakpoint_stack_snapshot

        reads = []

        class FakeGdb:
            def read_memory(self, address: int, size: int) -> bytes:
                reads.append((address, size))
                return bytes.fromhex("3412aabbccddeeff")

        snapshot = breakpoint_stack_snapshot(
            FakeGdb(),
            {"ss": 0x2567, "esp": 0x65C2},
        )
        self.assertEqual(reads, [(0x2BC32, 8)])
        self.assertEqual(
            snapshot,
            {
                "segment": 0x2567,
                "offset": 0x65C2,
                "linear": 0x2BC32,
                "size": 8,
                "bytes_hex": "3412aabbccddeeff",
                "near_return_offset": 0x1234,
            },
        )

    def test_running_breakpoint_halts_inserts_and_resumes(self) -> None:
        from dos_re_harness.remote_capture import install_running_breakpoint

        calls = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

        self.assertEqual(
            install_running_breakpoint(FakeGdb(), 0x1CC1C, 7.0),
            "S05",
        )
        self.assertEqual(
            calls,
            [("halt", 7.0), ("break", 0x1CC1C), ("continue",)],
        )

    def test_halted_breakpoint_can_be_cleared_before_chaining(self) -> None:
        from dos_re_harness.remote_capture import clear_halted_breakpoint

        calls = []

        class FakeGdb:
            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

        self.assertEqual(
            clear_halted_breakpoint(FakeGdb(), 0x850C, 7.0),
            "S05",
        )
        self.assertEqual(
            calls,
            [
                ("remove-break", 0x850C),
                ("step",),
                ("wait-stop", 7.0),
            ],
        )

    def test_halted_breakpoint_can_be_removed_without_stepping(self) -> None:
        from dos_re_harness.remote_capture import remove_halted_breakpoint

        calls = []

        class FakeGdb:
            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

        remove_halted_breakpoint(FakeGdb(), 0x8611)
        self.assertEqual(calls, [("remove-break", 0x8611)])

    def test_halted_segmented_breakpoint_is_removed_with_packed_address(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            remove_halted_segmented_breakpoint,
        )

        calls = []

        class FakeGdb:
            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

        self.assertEqual(
            remove_halted_segmented_breakpoint(
                FakeGdb(),
                0x0824,
                0x03D1,
            ),
            0x082403D1,
        )
        self.assertEqual(calls, [("remove-break", 0x082403D1)])

    def test_halted_cpu_can_be_poked_and_resumed_without_rehalting(self) -> None:
        from dos_re_harness.remote_capture import apply_halted_poke

        calls = []

        class FakeGdb:
            def write_memory(self, address: int, data: bytes) -> None:
                calls.append(("write", address, data))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

        apply_halted_poke(FakeGdb(), 0x8611, bytes.fromhex("ebfe"))
        self.assertEqual(
            calls,
            [
                ("write", 0x8611, bytes.fromhex("ebfe")),
                ("continue",),
            ],
        )

    def test_halted_cpu_can_resume_to_segmented_breakpoint(self) -> None:
        from dos_re_harness.remote_capture import install_halted_breakpoint

        calls = []

        class FakeGdb:
            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

        install_halted_breakpoint(FakeGdb(), 0x0824B3E6)
        self.assertEqual(
            calls,
            [("break", 0x0824B3E6), ("continue",)],
        )

    def test_halted_cpu_can_stop_on_chained_segmented_breakpoint(self) -> None:
        from dos_re_harness.remote_capture import stop_on_halted_breakpoint

        calls = []

        class FakeGdb:
            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

        self.assertEqual(
            stop_on_halted_breakpoint(FakeGdb(), 0x0824B3E6, 7.0),
            "S05",
        )
        self.assertEqual(
            calls,
            [
                ("break", 0x0824B3E6),
                ("continue",),
                ("wait-stop", 7.0),
            ],
        )

    def test_halted_segmented_breakpoint_returns_verified_registers(self) -> None:
        from dos_re_harness.remote_capture import (
            stop_on_halted_segmented_breakpoint,
        )

        calls = []

        class FakeGdb:
            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"cs": 0x0824, "eip": 0x13626}

        self.assertEqual(
            stop_on_halted_segmented_breakpoint(
                FakeGdb(),
                0x0824,
                0xB3E6,
                7.0,
            ),
            ("S05", {"cs": 0x0824, "eip": 0x13626}),
        )
        self.assertEqual(
            calls,
            [
                ("break", 0x0824B3E6),
                ("continue",),
                ("wait-stop", 7.0),
                ("registers",),
            ],
        )

        class WrongStopGdb(FakeGdb):
            def registers(self) -> dict[str, int]:
                return {"cs": 0x0824, "eip": 0x850C}

        with self.assertRaisesRegex(
            RuntimeError,
            "expected 0824:b3e6.*0x13626.*0x0850c",
        ):
            stop_on_halted_segmented_breakpoint(
                WrongStopGdb(),
                0x0824,
                0xB3E6,
                7.0,
            )

    def test_nth_breakpoint_stops_on_requested_hit(self) -> None:
        from dos_re_harness.remote_capture import stop_on_nth_breakpoint

        calls = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

        self.assertEqual(
            stop_on_nth_breakpoint(FakeGdb(), 0x13BE5, 2, 7.0),
            "S05",
        )
        self.assertEqual(
            calls,
            [
                ("halt", 7.0),
                ("break", 0x13BE5),
                ("continue",),
                ("wait-stop", 7.0),
                ("remove-break", 0x13BE5),
                ("step",),
                ("wait-stop", 7.0),
                ("break", 0x13BE5),
                ("continue",),
                ("wait-stop", 7.0),
            ],
        )
        with self.assertRaises(ValueError):
            stop_on_nth_breakpoint(FakeGdb(), 0x13BE5, 0, 7.0)

    def test_post_resume_nth_breakpoint_returns_stopped_registers(self) -> None:
        from dos_re_harness.remote_capture import (
            stop_on_post_resume_nth_breakpoint,
        )

        calls = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "T05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"eip": 0x1AAA7, "cs": 0x0824}

        stop, registers = stop_on_post_resume_nth_breakpoint(
            FakeGdb(),
            0x1AAA7,
            1,
            7.0,
        )

        self.assertEqual(stop, "T05")
        self.assertEqual(registers["eip"], 0x1AAA7)
        self.assertEqual(
            calls,
            [
                ("break", 0x1AAA7),
                ("continue",),
                ("wait-stop", 7.0),
                ("registers",),
            ],
        )

    def test_post_resume_breakpoint_series_captures_requested_hits(self) -> None:
        from dos_re_harness.remote_capture import (
            parse_breakpoint_hit_series,
            stop_on_post_resume_breakpoint_series,
        )

        calls = []
        captures = []

        class FakeGdb:
            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "T05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"eip": 0x1AAA7, "cs": 0x1764}

            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

        self.assertEqual(parse_breakpoint_hit_series("2,4,7"), [2, 4, 7])
        for invalid in ("", "0", "2,2", "4,2", "1,,2"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    parse_breakpoint_hit_series(invalid)

        stop, registers = stop_on_post_resume_breakpoint_series(
            FakeGdb(),
            0x1AAA7,
            [2, 4],
            7.0,
            lambda hit, item_stop, item_registers: captures.append(
                (hit, item_stop, item_registers["eip"])
            ),
        )

        self.assertEqual(stop, "T05")
        self.assertEqual(registers["eip"], 0x1AAA7)
        self.assertEqual(
            captures,
            [(2, "T05", 0x1AAA7), (4, "T05", 0x1AAA7)],
        )
        self.assertEqual(
            calls.count(("break", 0x1AAA7)),
            4,
        )
        self.assertEqual(
            calls.count(("continue",)),
            4,
        )

    def test_resume_checkpoint_accepts_natural_state_without_poke(
        self,
    ) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--resume-checkpoint-script",
                "checkpointstate:0x12340:frame_tick:23:4",
                "--resume-next-linear",
                "0x12343",
            ]
            with (
                patch("sys.argv", arguments),
                patch.object(
                    remote_capture,
                    "RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_interrupted_probe_manifest_records_direct_controls(self) -> None:
        from dos_re_harness.remote_capture import interrupted_probe_manifest

        arguments = type(
            "Arguments",
            (),
            {
                "poke": ["0x412bb:000000"],
                "poke_file": ["ds:0:snapshot.bin"],
                "call_near": 0x6F52,
                "call_near_break_linear": None,
                "call_near_break_segmented": None,
                "call_near_break_offset": None,
                "call_near_continue_after_return": True,
            },
        )()

        self.assertEqual(
            interrupted_probe_manifest(arguments),
            {
                "poke": ["0x412bb:000000"],
                "poke_file": ["ds:0:snapshot.bin"],
                "call_near": 0x6F52,
                "call_near_break_linear": None,
                "call_near_break_segmented": None,
                "call_near_break_offset": None,
                "call_near_continue_after_return": True,
            },
        )

    def test_resumed_checkpoint_namespaces_existing_state_path(self) -> None:
        from dos_re_harness.remote_capture import write_state_checkpoint

        class FakeQmp:
            def memdump(self, _address: int, size: int) -> bytes:
                return bytes(size)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkpoints"
            arguments = (
                FakeQmp(),
                root,
                "frame_tick",
                23,
                "S05",
                {"ds": 0},
                {"frame_tick": 23},
                1,
                "ds",
                8,
                False,
                0xA0000,
                16,
                b"P5\n4 4\n255\n",
            )
            first = write_state_checkpoint(
                *arguments,
                capture_vga=False,
            )
            resumed = write_state_checkpoint(
                *arguments,
                capture_vga=False,
                collision_namespace="resume",
            )

        self.assertEqual(
            Path(first["path"]),
            root / "frame_tick-23",
        )
        self.assertEqual(
            Path(resumed["path"]),
            root / "resume" / "frame_tick-23",
        )

    def test_post_resume_poke_can_continue_without_next_breakpoint(
        self,
    ) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--resume-checkpoint-script",
                "checkpointstate:0x12340:frame_tick:23:4",
                "--resume-next-linear",
                "0x12343",
                "--post-resume-break-segmented",
                "0x1111:0x20",
                "--post-resume-poke",
                "0x12000:ebfe",
                "--post-resume-continue-after-poke",
            ]
            with (
                patch("sys.argv", arguments),
                patch.object(
                    remote_capture,
                    "RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_post_resume_break_can_continue_without_mutating_guest(self) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--resume-checkpoint-script",
                "checkpointstate:0x12340:frame_tick:23:4",
                "--resume-next-linear",
                "0x12343",
                "--post-resume-break-segmented",
                "0x1111:0x20",
                "--post-resume-continue",
            ]
            with (
                patch("sys.argv", arguments),
                patch.object(
                    remote_capture,
                    "RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_post_resume_poke_can_apply_at_final_resumed_checkpoint(
        self,
    ) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--resume-checkpoint-script",
                "checkpointstate:0x12340:frame_tick:23:4",
                "--resume-next-linear",
                "0x12343",
                "--post-resume-break-segmented",
                "0x1111:0x20",
                "--post-resume-poke",
                "0x12000:ebfe",
            ]
            with (
                patch("sys.argv", arguments),
                patch.object(
                    remote_capture,
                    "RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_final_post_display_steps_past_installed_primary_breakpoint(
        self,
    ) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(
                remote_capture,
                "capture_post_display_screenshot",
            ) as capture:
                record = remote_capture.capture_final_post_display(
                    object(),
                    object(),
                    7.0,
                    (0x1111, 0x20),
                    (0x11130, b"\xeb\xfe"),
                    Path(temporary),
                    "S05",
                    "S05",
                    {"ds": 0x1234},
                    "ds",
                    0x10000,
                    0.05,
                    primary_breakpoint=0x850C,
                )

        self.assertEqual(record["primary_breakpoint"], 0x850C)
        self.assertTrue(
            capture.call_args.kwargs["primary_breakpoint_installed"]
        )

    def test_post_resume_poke_accepts_next_breakpoint_hit_series(
        self,
    ) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--resume-checkpoint-script",
                "checkpointstate:0x12340:frame_tick:23:4",
                "--resume-next-linear",
                "0x12343",
                "--post-resume-break-segmented",
                "0x1111:0x20",
                "--post-resume-poke",
                "0x12000:ebfe",
                "--post-resume-next-break-segmented",
                "0x2222:0x40",
                "--post-resume-next-break-hit-series",
                "1,3,7",
            ]
            with (
                patch("sys.argv", arguments),
                patch.object(
                    remote_capture,
                    "RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_post_resume_segmented_breakpoint_uses_backend_address(self) -> None:
        from dos_re_harness.remote_capture import (
            stop_on_post_resume_nth_segmented_breakpoint,
        )

        calls = []

        class FakeGdb:
            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "T05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"eip": 0x1AAA7, "cs": 0x1764}

        stop, registers = stop_on_post_resume_nth_segmented_breakpoint(
            FakeGdb(),
            0x1764,
            0x3467,
            1,
            7.0,
        )

        self.assertEqual(stop, "T05")
        self.assertEqual(registers["eip"], 0x1AAA7)
        self.assertEqual(
            calls,
            [
                ("break", 0x17643467),
                ("continue",),
                ("wait-stop", 7.0),
                ("registers",),
            ],
        )

    def test_post_resume_poke_files_write_chunked_with_manifest(self) -> None:
        from dos_re_harness.remote_capture import apply_halted_poke_files

        calls = []

        class FakeGdb:
            def write_memory_chunked(self, address: int, data: bytes) -> None:
                calls.append((address, data))

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as tmp:
            payload = Path(tmp) / "sentinel.bin"
            payload.write_bytes(b"\x7f\x80\x81")
            relative_payload = payload.relative_to(Path.cwd())
            writes = apply_halted_poke_files(
                FakeGdb(),
                [
                    f"0xa0000:{relative_payload}",
                    f"ds:0x12:{relative_payload}",
                ],
                {"ds": 0x1234},
            )

        self.assertEqual(
            calls,
            [
                (0xA0000, b"\x7f\x80\x81"),
                (0x12352, b"\x7f\x80\x81"),
            ],
        )
        self.assertEqual(
            [write["address"] for write in writes],
            [0xA0000, 0x12352],
        )
        self.assertEqual([write["size"] for write in writes], [3, 3])
        self.assertEqual(
            writes[0]["sha256"],
            hashlib.sha256(b"\x7f\x80\x81").hexdigest(),
        )

    def test_state_breakpoint_stops_on_matching_schema_value(self) -> None:
        from dos_re_harness.remote_capture import (
            parse_segmented_state_breakpoint_action,
            parse_state_breakpoint_action,
            stop_on_state_breakpoint,
        )

        self.assertEqual(
            parse_state_breakpoint_action(
                "breakstate:0x850c:loop_tick==44:64"
            ),
            (0x850C, ("loop_tick", "==", 44), 64),
        )
        self.assertEqual(
            parse_segmented_state_breakpoint_action(
                "breakstatesso:0x0824:0x932c:loop_tick==50:128"
            ),
            (0x0824932C, ("loop_tick", "==", 50), 128),
        )
        with self.assertRaises(ValueError):
            parse_state_breakpoint_action(
                "breakstate:0x850c:loop_tick==44:0"
            )

        calls = []
        states = iter(({"loop_tick": 43}, {"loop_tick": 44}))

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"ds": 0x2567}

            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

        result = stop_on_state_breakpoint(
            FakeGdb(),
            0x850C,
            ("loop_tick", "==", 44),
            64,
            7.0,
            lambda _registers: next(states),
        )
        self.assertEqual(
            result,
            ("S05", {"ds": 0x2567}, {"loop_tick": 44}, 2),
        )
        self.assertEqual(
            calls,
            [
                ("halt", 7.0),
                ("break", 0x850C),
                ("continue",),
                ("wait-stop", 7.0),
                ("registers",),
                ("remove-break", 0x850C),
                ("step",),
                ("wait-stop", 7.0),
                ("break", 0x850C),
                ("continue",),
                ("wait-stop", 7.0),
                ("registers",),
            ],
        )

    def test_state_checkpoints_capture_ordered_schema_values(self) -> None:
        from dos_re_harness.remote_capture import (
            load_state_input_script,
            merged_state_script_values,
            parse_state_checkpoint_action,
            parse_state_checkpoint_hold_action,
            parse_state_checkpoint_script_action,
            parse_state_checkpoint_script_file_action,
            prepare_restore_halt,
            resumed_state_checkpoint_plan,
            resumed_state_script_plan,
            resumed_state_script_plan_with_held,
            stop_on_state_checkpoints,
            write_state_checkpoint,
        )

        self.assertEqual(
            parse_state_checkpoint_action(
                "checkpointstate:0x850c:loop_tick:182+183+184:246"
            ),
            (0x850C, "loop_tick", [182, 183, 184], 246),
        )
        for invalid in (
            "checkpointstate:0x850c:loop_tick::246",
            "checkpointstate:0x850c:loop_tick:182+182:246",
            "checkpointstate:0x850c:loop_tick:182:0",
        ):
            with self.assertRaises(ValueError):
                parse_state_checkpoint_action(invalid)

        self.assertEqual(
            parse_state_checkpoint_hold_action(
                "checkpointstatehold:"
                "0x850c:loop_tick:40+41+42+43+44+45+46+47:112:"
                "left:42:47"
            ),
            (
                0x850C,
                "loop_tick",
                [40, 41, 42, 43, 44, 45, 46, 47],
                112,
                "left",
                42,
                47,
            ),
        )
        self.assertEqual(
            parse_state_checkpoint_hold_action(
                "checkpointstatehold:"
                "0x850c:loop_tick:42+43+44:112:"
                "left+spc:42:44"
            )[4],
            "left+spc",
        )
        for invalid in (
            "checkpointstatehold:"
            "0x850c:loop_tick:42+43:112:left:42:44",
            "checkpointstatehold:"
            "0x850c:loop_tick:42+43:112:left:43:42",
            "checkpointstatehold:"
            "0x850c:loop_tick:42+43:112::42:43",
        ):
            with self.assertRaises(ValueError):
                parse_state_checkpoint_hold_action(invalid)

        self.assertEqual(
            parse_state_checkpoint_script_action(
                "checkpointstatescript:"
                "0x850c:loop_tick:42+43+44+45+46+47+48+49+50:112:"
                "42=down.left+spc~47=up.spc~50=up.left"
            ),
            (
                0x850C,
                "loop_tick",
                [42, 43, 44, 45, 46, 47, 48, 49, 50],
                112,
                [
                    (42, True, ["left", "spc"]),
                    (47, False, ["spc"]),
                    (50, False, ["left"]),
                ],
            ),
        )
        self.assertEqual(
            parse_state_checkpoint_script_file_action(
                "checkpointstatescriptfile:"
                "0x850c:loop_tick:40+45+50:112"
            ),
            (0x850C, "loop_tick", [40, 45, 50], 112),
        )
        self.assertEqual(
            resumed_state_checkpoint_plan(
                "checkpointstate:"
                "0x850c:loop_tick:1000+1050+1100:164",
                [(1001, True, ["left"])],
            ),
            (
                0x850C,
                "loop_tick",
                [1000, 1050, 1100],
                [1000, 1050, 1100],
                164,
                [],
                [],
            ),
        )
        self.assertEqual(
            resumed_state_checkpoint_plan(
                "checkpointstatescriptfile:"
                "0x850c:loop_tick:1000+1050+1100:164",
                [
                    (999, True, ["left"]),
                    (999, False, ["left"]),
                    (1050, True, ["right"]),
                    (1051, False, ["right"]),
                ],
            ),
            (
                0x850C,
                "loop_tick",
                [1000, 1050, 1100],
                [1000, 1050, 1051, 1100],
                164,
                [
                    (1050, True, ["right"]),
                    (1051, False, ["right"]),
                ],
                [],
            ),
        )
        self.assertEqual(
            resumed_state_checkpoint_plan(
                "checkpointstatescriptfile:"
                "0x850c:loop_tick:1000+1050+1100:164",
                [(1050, False, ["up"])],
                initial_held_qcodes=["left", "up"],
            ),
            (
                0x850C,
                "loop_tick",
                [1000, 1050, 1100],
                [1000, 1050, 1100],
                164,
                [(1050, False, ["up"])],
                ["left", "up"],
            ),
        )
        for invalid in (
            "checkpointstatescript:"
            "0x850c:loop_tick:42+43:112:44=down.left",
            "checkpointstatescript:"
            "0x850c:loop_tick:42+43:112:42=press.left",
            "checkpointstatescript:"
            "0x850c:loop_tick:42+43:112:42=down.",
        ):
            with self.assertRaises(ValueError):
                parse_state_checkpoint_script_action(invalid)

        with tempfile.TemporaryDirectory() as temporary:
            script_path = Path(temporary) / "mission.input.script"
            script_path.write_text(
                "\n".join(
                    [
                        "dos-re-state-input-script-v1",
                        "# state_field=loop_tick",
                        "# terminal_value=50",
                        "42=down.left+spc",
                        "47=up.spc",
                        "50=up.left",
                        "",
                    ]
                ),
                encoding="utf-8",
            )
            metadata, file_events = load_state_input_script(script_path)
        self.assertEqual(
            metadata,
            {"state_field": "loop_tick", "terminal_value": "50"},
        )
        self.assertEqual(
            file_events,
            [
                (42, True, ["left", "spc"]),
                (47, False, ["spc"]),
                (50, False, ["left"]),
            ],
        )
        self.assertEqual(
            merged_state_script_values(
                [40, 45, 50],
                [
                    *file_events,
                    (60, True, ["right"]),
                    (61, False, ["right"]),
                ],
            ),
            [40, 42, 45, 47, 50],
        )
        self.assertEqual(
            resumed_state_script_plan(
                [50, 55, 60],
                [
                    (42, True, ["left"]),
                    (47, False, ["left"]),
                    (52, True, ["right"]),
                    (54, False, ["right"]),
                    (65, True, ["spc"]),
                    (66, False, ["spc"]),
                ],
            ),
            (
                [50, 52, 54, 55, 60],
                [
                    (52, True, ["right"]),
                    (54, False, ["right"]),
                ],
            ),
        )
        with self.assertRaisesRegex(
            ValueError,
            "neutral keyboard boundary",
        ):
            resumed_state_script_plan(
                [50, 55],
                [
                    (49, True, ["left"]),
                    (52, False, ["left"]),
                ],
            )
        self.assertEqual(
            resumed_state_script_plan_with_held(
                [50, 55],
                [
                    (48, True, ["left", "spc"]),
                    (52, False, ["spc"]),
                    (54, False, ["left"]),
                ],
            ),
            (
                [50, 52, 54, 55],
                [
                    (52, False, ["spc"]),
                    (54, False, ["left"]),
                ],
                ["left", "spc"],
            ),
        )

        class AlreadyHaltedGdb:
            def halt(self, _timeout: float) -> str:
                raise AssertionError("must not halt an already halted target")

            def registers(self) -> dict[str, int]:
                raise AssertionError(
                    "must reuse registers from the existing halt"
                )

        self.assertEqual(
            prepare_restore_halt(
                AlreadyHaltedGdb(),
                7.0,
                "S05",
                {"ds": 0x2567},
            ),
            ("S05", {"ds": 0x2567}),
        )

        with tempfile.TemporaryDirectory() as temporary:
            qmp_calls = []

            class StateOnlyQmp:
                def memdump(self, address: int, size: int) -> bytes:
                    qmp_calls.append((address, size))
                    return bytes(size)

            checkpoint = Path(temporary) / "checkpoints"
            write_state_checkpoint(
                StateOnlyQmp(),
                checkpoint,
                "loop_tick",
                50,
                "S05",
                {"ds": 0x2567},
                {"loop_tick": 50},
                1,
                "ds",
                8,
                False,
                0xA0000,
                16,
                b"P5\n4 4\n255\n",
                capture_vga=False,
            )
            checkpoint_path = checkpoint / "loop_tick-50"
            metadata = json.loads(
                (
                    checkpoint_path / "remote_runtime_registers.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(qmp_calls, [(0x25670, 8)])
            self.assertIsNone(metadata["vga_dump"])
            self.assertIsNone(metadata["vga_pgm"])
            self.assertFalse(
                (checkpoint_path / "remote_runtime_vga.bin").exists()
            )


        calls = []
        states = iter(
            (
                {"loop_tick": 181},
                {"loop_tick": 182},
                {"loop_tick": 183},
            )
        )
        captured = []
        transitions = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"ds": 0x2567}

            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

        result = stop_on_state_checkpoints(
            FakeGdb(),
            0x850C,
            "loop_tick",
            [182, 183],
            8,
            7.0,
            lambda _registers: next(states),
            lambda value, stop, registers, state, hit: captured.append(
                (value, stop, registers, state, hit)
            ),
            transitions.append,
        )
        self.assertEqual(
            result,
            ("S05", {"ds": 0x2567}, {"loop_tick": 183}, 3),
        )
        self.assertEqual(
            [(item[0], item[4]) for item in captured],
            [(182, 2), (183, 3)],
        )
        self.assertEqual(transitions, [182, 183])
        self.assertEqual(
            calls.count(("remove-break", 0x850C)),
            2,
        )
        self.assertEqual(calls.count(("step",)), 2)

    def test_state_checkpoints_trace_concurrent_side_breakpoint(self) -> None:
        from dos_re_harness.remote_capture import stop_on_state_checkpoints

        calls = []
        registers = iter(
            (
                {"eip": (0x4122 << 4) + 0x26E5, "ds": 0x2567},
                {"eip": 0x850C, "ds": 0x2567},
                {"eip": 0x850C, "ds": 0x2567},
            )
        )
        states = iter(({"loop_tick": 10}, {"loop_tick": 11}))
        primary = []
        side = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def insert_breakpoint(self, address: int) -> None:
                calls.append(("break", address))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-stop", timeout))
                return "S05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return next(registers)

            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-break", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

        result = stop_on_state_checkpoints(
            FakeGdb(),
            0x850C,
            "loop_tick",
            [10, 11],
            4,
            7.0,
            lambda _registers: next(states),
            lambda value, _stop, _registers, _state, hit: primary.append(
                (value, hit)
            ),
            side_breakpoint=(0x412226E5, (0x4122 << 4) + 0x26E5),
            side_capture=lambda hit, _stop, _registers: side.append(hit),
            side_max_hits=1,
        )
        self.assertEqual(
            result,
            ("S05", {"eip": 0x850C, "ds": 0x2567}, {"loop_tick": 11}, 2),
        )
        self.assertEqual(primary, [(10, 1), (11, 2)])
        self.assertEqual(side, [1])
        self.assertIn(("break", 0x850C), calls)
        self.assertIn(("break", 0x412226E5), calls)
        self.assertIn(("remove-break", 0x412226E5), calls)

    def test_state_checkpoint_writes_complete_nested_snapshot(self) -> None:
        from dos_re_harness.remote_capture import write_state_checkpoint

        class FakeQmp:
            def memdump(self, address: int, size: int) -> bytes:
                return bytes([address & 0xFF]) * size

            def dacdump(self) -> dict[str, object]:
                return {
                    "data": bytes(range(256)) * 3,
                    "bits": 6,
                    "pel_mask": 0xFF,
                    "pel_index": 7,
                    "state": 0,
                    "write_index": 8,
                    "read_index": 9,
                    "first_changed": 16,
                }

            def displaydump(self) -> dict[str, object]:
                return {
                    "data": bytes((1, 2, 3, 4)),
                    "width": 2,
                    "height": 2,
                    "bpp": 8,
                    "pitch": 2,
                    "generation": 17,
                }

            def screendump(self) -> bytes:
                return b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND"

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkpoints"
            record = write_state_checkpoint(
                FakeQmp(),
                root,
                "loop_tick",
                183,
                "S05",
                {"ds": 0x1234, "eip": 0x850C},
                {"loop_tick": 183},
                245,
                "ds",
                8,
                False,
                0xA0000,
                4,
                b"P5\n2 2\n255\n",
                capture_dac=True,
                capture_display=True,
                capture_screenshot=True,
            )
            checkpoint = root / "loop_tick-183"
            self.assertEqual(record["path"], str(checkpoint))
            self.assertEqual(
                (checkpoint / "remote_runtime_ds.bin").read_bytes(),
                b"\x40" * 8,
            )
            self.assertEqual(
                (checkpoint / "remote_runtime_vga.pgm").read_bytes(),
                b"P5\n2 2\n255\n" + b"\x00" * 4,
            )
            self.assertEqual(
                (checkpoint / "remote_runtime_screen.png").read_bytes(),
                b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND",
            )
            self.assertEqual(
                (checkpoint / "remote_runtime_dac.bin").read_bytes(),
                bytes(range(256)) * 3,
            )
            self.assertEqual(
                (checkpoint / "remote_runtime_display.bin").read_bytes(),
                bytes((1, 2, 3, 4)),
            )
            registers = json.loads(
                (
                    checkpoint / "remote_runtime_registers.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(
                registers["state_checkpoint"]["matched_hit"],
                245,
            )
            self.assertEqual(
                registers["screenshot"],
                str(checkpoint / "remote_runtime_screen.png"),
            )
            self.assertEqual(registers["dac"]["bits"], 6)
            self.assertEqual(registers["dac"]["first_changed"], 16)
            self.assertEqual(registers["display"]["width"], 2)
            self.assertEqual(registers["display"]["height"], 2)
            self.assertEqual(registers["display"]["bpp"], 8)
            self.assertEqual(registers["display"]["generation"], 17)
            self.assertIsNone(registers["screenshot_error"])
            self.assertTrue(registers["screenshot_exact_checkpoint"])
            self.assertFalse(registers["screenshot_deferred_side_effect"])

    def test_state_checkpoint_uses_chunked_memory_for_all_large_reads(self) -> None:
        from dos_re_harness.remote_capture import write_state_checkpoint

        calls = []

        class ChunkedQmp:
            def memdump(self, _address: int, _size: int) -> bytes:
                raise AssertionError("large checkpoint read bypassed chunking")

            def memdump_chunked(self, address: int, size: int) -> bytes:
                calls.append((address, size))
                return bytes(size)

        with tempfile.TemporaryDirectory() as temporary:
            write_state_checkpoint(
                ChunkedQmp(),
                Path(temporary) / "checkpoints",
                "loop_tick",
                3000,
                "S05",
                {"ds": 0x1234, "eip": 0x850C},
                {"loop_tick": 3000},
                1,
                "ds",
                8,
                True,
                0xA0000,
                4,
                b"P5\n2 2\n255\n",
            )

        self.assertEqual(
            calls,
            [
                (0x12340, 8),
                (0xA0000, 4),
                (0, 0xA0000),
            ],
        )

    def test_qmp_full_save_state_commands_preserve_exact_backend_path(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import QmpClient

        calls = []
        client = QmpClient.__new__(QmpClient)

        def command(
            execute,
            arguments=None,
            timeout=None,
            sent_event=None,
        ):
            calls.append((execute, arguments, timeout, sent_event))
            return {"return": {"file": arguments["file"]}}

        client.command = command
        state_path = Path("/capture/checkpoints/frame-40/runtime.sav")

        self.assertEqual(client.save_state(state_path), state_path)
        self.assertEqual(client.load_state(state_path), state_path)
        self.assertEqual(
            [call[:3] for call in calls],
            [
                ("savestate", {"file": str(state_path)}, 35.0),
                ("loadstate", {"file": str(state_path)}, 35.0),
            ],
        )
        self.assertIsNone(calls[0][3])

    def test_qmp_memdump_falls_back_to_rsp_after_timeout(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        client.command = lambda *args, **kwargs: (_ for _ in ()).throw(
            TimeoutError("qmp stalled")
        )
        fallback_calls = []

        def fallback(address: int, size: int) -> bytes:
            fallback_calls.append((address, size))
            return bytes([0xA5]) * size

        QmpClient.set_memory_fallback(fallback)
        self.addCleanup(QmpClient.set_memory_fallback, None)
        self.assertEqual(client.memdump(0x12340, 8), bytes([0xA5]) * 8)
        self.assertEqual(fallback_calls, [(0x12340, 8)])

    def test_qmp_memdump_chunked_bounds_each_request(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        calls = []

        def memdump(address: int, size: int) -> bytes:
            calls.append((address, size))
            return bytes([address & 0xFF]) * size

        client.memdump = memdump
        self.assertEqual(
            client.memdump_chunked(0x1200, 10, chunk_size=4),
            bytes([0x00]) * 4 + bytes([0x04]) * 4 + bytes([0x08]) * 2,
        )
        self.assertEqual(
            calls,
            [(0x1200, 4), (0x1204, 4), (0x1208, 2)],
        )

    def test_qmp_dacdump_decodes_palette_and_state(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        palette = bytes(range(256)) * 3

        def command(execute, arguments=None, timeout=None, sent_event=None):
            self.assertEqual(execute, "dacdump")
            self.assertIsNone(arguments)
            self.assertIsNone(timeout)
            self.assertIsNone(sent_event)
            return {
                "return": {
                    "data": base64.b64encode(palette).decode("ascii"),
                    "bits": 6,
                    "pel_mask": 255,
                    "pel_index": 2,
                    "state": 1,
                    "write_index": 12,
                    "read_index": 11,
                    "first_changed": 256,
                }
            }

        client.command = command
        result = client.dacdump()
        self.assertEqual(result["data"], palette)
        self.assertEqual(result["bits"], 6)
        self.assertEqual(result["write_index"], 12)

    def test_qmp_displaydump_decodes_completed_source_frame(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        pixels = bytes((1, 2, 3, 4))

        def command(execute, arguments=None, timeout=None, sent_event=None):
            self.assertEqual(execute, "displaydump")
            self.assertIsNone(arguments)
            self.assertIsNone(timeout)
            self.assertIsNone(sent_event)
            return {
                "return": {
                    "data": base64.b64encode(pixels).decode("ascii"),
                    "size": len(pixels),
                    "width": 2,
                    "height": 2,
                    "bpp": 8,
                    "pitch": 2,
                    "generation": 17,
                }
            }

        client.command = command
        result = client.displaydump()
        self.assertEqual(result["data"], pixels)
        self.assertEqual(result["width"], 2)
        self.assertEqual(result["height"], 2)
        self.assertEqual(result["bpp"], 8)
        self.assertEqual(result["pitch"], 2)
        self.assertEqual(result["generation"], 17)

        client.command = lambda _execute: {
            "return": {
                "data": base64.b64encode(pixels[:-1]).decode("ascii"),
                "size": len(pixels) - 1,
                "width": 2,
                "height": 2,
                "bpp": 8,
                "pitch": 2,
                "generation": 18,
            }
        }
        with self.assertRaisesRegex(RuntimeError, "unexpected frame size"):
            client.displaydump()

    def test_qmp_display_history_retains_fast_completed_frames(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        calls = []
        frames = [bytes((1, 2, 3, 4)), bytes((5, 6, 7, 8))]
        palettes = [bytes([17]) * 768, bytes([18]) * 768]

        def command(execute, arguments=None, timeout=None, sent_event=None):
            calls.append((execute, arguments, timeout, sent_event))
            if execute == "displayhistory-start":
                return {"return": {"capacity": 8, "generation": 16}}
            self.assertEqual(execute, "displayhistory-stop")
            return {
                "return": {
                    "capacity": 8,
                    "dropped": 0,
                    "frames": [
                        {
                            "data": base64.b64encode(
                                data if generation == 17 else zlib.compress(data)
                            ).decode("ascii"),
                            "encoding": (
                                "raw" if generation == 17 else "zlib"
                            ),
                            "size": len(data),
                            "width": 2,
                            "height": 2,
                            "bpp": 8,
                            "pitch": 2,
                            "generation": generation,
                            "palette": base64.b64encode(
                                palettes[generation - 17]
                            ).decode("ascii"),
                            "palette_size": 768,
                        }
                        for generation, data in zip((17, 18), frames)
                    ],
                }
            }

        client.command = command
        started = client.start_display_history(8)
        history = client.stop_display_history()

        self.assertEqual(started["generation"], 16)
        self.assertEqual(history["capacity"], 8)
        self.assertEqual(history["dropped"], 0)
        self.assertEqual(
            [frame["generation"] for frame in history["frames"]],
            [17, 18],
        )
        self.assertEqual(
            [frame["data"] for frame in history["frames"]],
            frames,
        )
        self.assertEqual(
            [frame["palette"] for frame in history["frames"]],
            palettes,
        )
        self.assertEqual(
            calls,
            [
                ("displayhistory-start", {"capacity": 8}, None, None),
                ("displayhistory-stop", None, None, None),
            ],
        )

    def test_display_history_writer_retains_generation_and_pixels(self) -> None:
        from dos_re_harness.remote_capture import write_display_history

        history = {
            "capacity": 8,
            "dropped": 0,
            "frames": [
                {
                    "data": bytes((1, 2, 3, 4)),
                    "width": 2,
                    "height": 2,
                    "bpp": 8,
                    "pitch": 2,
                    "generation": 17,
                    "palette": bytes([17]) * 768,
                },
                {
                    "data": bytes((5, 6, 7, 8)),
                    "width": 2,
                    "height": 2,
                    "bpp": 8,
                    "pitch": 2,
                    "generation": 18,
                    "palette": bytes([18]) * 768,
                },
            ],
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            record = write_display_history(
                root,
                {"capacity": 8, "generation": 16},
                history,
            )

            self.assertEqual(record["first_generation"], 17)
            self.assertEqual(record["last_generation"], 18)
            self.assertEqual(record["frame_count"], 2)
            self.assertEqual(
                (root / "post_resume_display_history" /
                 "frame_0001.display.bin").read_bytes(),
                bytes((5, 6, 7, 8)),
            )
            self.assertEqual(
                (root / "post_resume_display_history" /
                 "frame_0001.palette.bin").read_bytes(),
                bytes([18]) * 768,
            )
            manifest = json.loads(
                (root / "post_resume_display_history.json").read_text(
                    encoding="utf-8"
                )
            )
            self.assertEqual(manifest["start_generation"], 16)
            self.assertEqual(manifest["frames"][0]["generation"], 17)
            self.assertEqual(manifest["frames"][0]["palette"]["size"], 768)
            self.assertEqual(
                manifest["frames"][0]["palette"]["sha256"],
                hashlib.sha256(bytes([17]) * 768).hexdigest(),
            )

    def test_timed_vga_sample_retains_palette_evidence(self) -> None:
        from dos_re_harness.remote_capture import (
            write_vga_dac_sequence_sample,
        )

        with tempfile.TemporaryDirectory() as temporary:
            sequence_dir = Path(temporary)
            vga = bytes([1, 2, 3, 4])
            palette = bytes(range(256)) * 3
            sample = write_vga_dac_sequence_sample(
                sequence_dir,
                7,
                vga,
                {
                    "data": palette,
                    "bits": 6,
                    "pel_mask": 255,
                    "pel_index": 2,
                    "state": 1,
                    "write_index": 12,
                    "read_index": 11,
                    "first_changed": 16,
                },
            )

            self.assertEqual(
                (sequence_dir / "frame_0007.bin").read_bytes(),
                vga,
            )
            self.assertEqual(
                (sequence_dir / "frame_0007.dac.bin").read_bytes(),
                palette,
            )
            self.assertEqual(sample["path"], str(sequence_dir / "frame_0007.bin"))
            self.assertEqual(
                sample["dac"]["path"],
                str(sequence_dir / "frame_0007.dac.bin"),
            )
            self.assertEqual(sample["dac"]["bits"], 6)
            self.assertEqual(sample["dac"]["first_changed"], 16)
            self.assertEqual(sample["dac"]["size"], 768)
            self.assertEqual(
                sample["dac"]["sha256"],
                hashlib.sha256(palette).hexdigest(),
            )

    def test_timed_vga_sample_can_retain_memory_snapshot(self) -> None:
        from dos_re_harness.remote_capture import (
            write_vga_dac_sequence_sample,
        )

        with tempfile.TemporaryDirectory() as temporary:
            sequence_dir = Path(temporary)
            memory = bytes([0x12, 0x34, 0x56])
            sample = write_vga_dac_sequence_sample(
                sequence_dir,
                3,
                b"vga",
                {
                    "data": bytes(range(256)) * 3,
                    "bits": 6,
                    "pel_mask": 255,
                    "pel_index": 0,
                    "state": 1,
                    "write_index": 0,
                    "read_index": 0,
                    "first_changed": 256,
                },
                memory_data=memory,
                memory_segment="ds",
            )
            memory_path = sequence_dir / "frame_0003.ds.bin"
            self.assertEqual(memory_path.read_bytes(), memory)
            self.assertEqual(sample["memory"]["segment"], "ds")
            self.assertEqual(sample["memory"]["path"], str(memory_path))
            self.assertEqual(sample["memory"]["size"], len(memory))
            self.assertEqual(
                sample["memory"]["sha256"],
                hashlib.sha256(memory).hexdigest(),
            )

    def test_qmp_screendump_rejects_empty_payload(self) -> None:
        from dos_re_harness.remote_capture import QmpClient

        client = QmpClient.__new__(QmpClient)
        client.command = lambda *args, **kwargs: {"return": {"data": ""}}
        with self.assertRaisesRegex(RuntimeError, "empty payload"):
            client.screendump()

    def test_state_checkpoint_can_write_full_emulator_save_state(self) -> None:
        from dos_re_harness.remote_capture import (
            finalize_halted_checkpoint_save_state,
            write_state_checkpoint,
        )

        calls = []

        class FakeQmp:
            def memdump(self, address: int, size: int) -> bytes:
                return bytes([address & 0xFF]) * size

            def save_state(self, path: Path, request_sent=None) -> Path:
                calls.append(("save-state", path))
                request_sent.set()
                path.write_bytes(b"cpu-ram-vram-registers-dac")
                return path

        class FakeGdb:
            def remove_breakpoint(self, address: int) -> None:
                calls.append(("remove-breakpoint", address))

            def step_nowait(self) -> None:
                calls.append(("step",))

            def wait_for_stop(self, timeout: float) -> str:
                calls.append(("wait-for-stop", timeout))
                return "S05"

            def continue_nowait(self) -> None:
                calls.append(("continue",))

            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def registers(self) -> dict[str, int]:
                calls.append(("registers",))
                return {"ds": 0x1234, "eip": 0x12343}

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "checkpoints"
            record = write_state_checkpoint(
                FakeQmp(),
                root,
                "frame_tick",
                40,
                "S05",
                {"ds": 0x1234, "eip": 0x12340},
                {"frame_tick": 40},
                9,
                "ds",
                8,
                False,
                0xA0000,
                4,
                b"P5\n2 2\n255\n",
            )
            stop, registers = finalize_halted_checkpoint_save_state(
                FakeQmp(),
                FakeGdb(),
                0x12340,
                record,
                10.0,
                lambda _registers: {"frame_tick": 44},
            )
            checkpoint = root / "frame_tick-40"
            save_state = checkpoint / "remote_runtime.sav"
            metadata = json.loads(
                (
                    checkpoint / "remote_runtime_registers.json"
                ).read_text(encoding="utf-8")
            )
            save_state_bytes = save_state.read_bytes()

        self.assertEqual(
            save_state_bytes,
            b"cpu-ram-vram-registers-dac",
        )
        self.assertEqual(metadata["save_state"], str(save_state))
        self.assertEqual(
            metadata["save_state_size"],
            len(b"cpu-ram-vram-registers-dac"),
        )
        self.assertEqual(
            metadata["save_state_sha256"],
            hashlib.sha256(b"cpu-ram-vram-registers-dac").hexdigest(),
        )
        self.assertEqual(record["save_state"], str(save_state))
        self.assertEqual(
            record["save_state_resume"]["post_save_state"],
            {"frame_tick": 44},
        )
        self.assertEqual(
            record["save_state_sha256"],
            metadata["save_state_sha256"],
        )
        self.assertEqual(stop, "S05")
        self.assertEqual(registers["eip"], 0x12343)
        self.assertEqual(
            calls,
            [
                ("remove-breakpoint", 0x12340),
                ("step",),
                ("wait-for-stop", 10.0),
                ("save-state", save_state),
                ("continue",),
                ("halt", 10.0),
                ("registers",),
            ],
        )

    def test_checkpoint_save_state_accepts_post_resume_next_boundary(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import checkpoint_save_state_target

        self.assertEqual(
            checkpoint_save_state_target(
                True,
                [],
                "checkpointstate:0x12340:frame_tick:40:100",
                True,
            ),
            "post_resume_next",
        )
        self.assertEqual(
            checkpoint_save_state_target(
                True,
                [],
                "checkpointstate:0x12340:frame_tick:40:100",
                False,
            ),
            "resume_final",
        )
        self.assertEqual(
            checkpoint_save_state_target(
                True,
                [],
                "checkpointstate:0x12340:frame_tick:40:100",
                False,
                save_state_first=True,
            ),
            "post_resume_first",
        )
        with self.assertRaisesRegex(
            ValueError,
            "first post-resume save-state requires",
        ):
            checkpoint_save_state_target(
                True,
                [],
                None,
                False,
                save_state_first=True,
            )
        self.assertEqual(
            checkpoint_save_state_target(
                True,
                ["rununtilstop:120"],
                None,
                False,
                "65536",
            ),
            "state_input_stop",
        )
        self.assertEqual(
            checkpoint_save_state_target(
                True,
                [],
                None,
                False,
                "65536",
                True,
            ),
            "state_input_stop",
        )
        self.assertEqual(
            checkpoint_save_state_target(
                True,
                ["checkpointstate:0x12340:frame_tick:40:100"],
                None,
                False,
            ),
            "startup",
        )

    def test_load_state_readiness_waits_for_a_completed_guest_screen(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import wait_for_qmp_screen

        frames = iter((b"boot", b"transition", b"intro"))

        class FakeQmp:
            def memdump(self, address: int, size: int) -> bytes:
                self.last_request = (address, size)
                return next(frames)

        class FakeClassifier:
            def classify(self, raw: bytes) -> str:
                return raw.decode("ascii")

        qmp = FakeQmp()
        matched = wait_for_qmp_screen(
            qmp,
            FakeClassifier(),
            0xA0000,
            64000,
            "intro",
            1.0,
            0.0,
        )
        self.assertEqual(matched, b"intro")
        self.assertEqual(qmp.last_request, (0xA0000, 64000))

    def test_full_state_resume_accepts_an_in_tick_instruction(self) -> None:
        from dos_re_harness.remote_capture import validate_resume_bootstrap

        validate_resume_bootstrap(
            {"eip": 0x22222},
            {"frame_tick": 40},
            "frame_tick",
            40,
            0x12343,
            full_state_loaded=True,
        )
        with self.assertRaisesRegex(ValueError, "wrong next instruction"):
            validate_resume_bootstrap(
                {"eip": 0x22222},
                {"frame_tick": 40},
                "frame_tick",
                40,
                0x12343,
                full_state_loaded=False,
            )

    def test_full_state_provenance_binds_companion_metadata(self) -> None:
        from dos_re_harness.remote_capture import (
            load_save_state_checkpoint_metadata,
        )

        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary)
            state_path = checkpoint / "remote_runtime.sav"
            state_path.write_bytes(b"complete-machine-state")
            digest = hashlib.sha256(b"complete-machine-state").hexdigest()
            (
                checkpoint / "remote_runtime_registers.json"
            ).write_text(
                json.dumps(
                    {
                        "dump_segment_value": 0x2345,
                        "save_state": str(state_path),
                        "save_state_sha256": digest,
                    }
                ),
                encoding="utf-8",
            )
            metadata = load_save_state_checkpoint_metadata(state_path)

        self.assertEqual(metadata["dump_segment_value"], 0x2345)
        self.assertEqual(metadata["save_state_sha256"], digest)

    def test_post_resume_next_checkpoint_supports_post_display_capture(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            capture_post_resume_next_display,
        )

        record = {"path": "checkpoint"}
        with patch(
            "dos_re_harness.remote_capture.capture_configured_post_display"
        ) as capture:
            capture_post_resume_next_display(
                object(),
                object(),
                30.0,
                (0x1234, 0x5678),
                (0x179B8, b"\xeb\xfe"),
                record,
                0x12340,
                0.05,
            )

        self.assertEqual(record["primary_breakpoint"], 0x12340)
        capture.assert_called_once_with(
            unittest.mock.ANY,
            unittest.mock.ANY,
            30.0,
            (0x1234, 0x5678),
            (0x179B8, b"\xeb\xfe"),
            record,
            0x12340,
            0.05,
        )

    def test_post_display_scope_can_skip_preparatory_checkpoints(self) -> None:
        from dos_re_harness.remote_capture import checkpoint_post_display_enabled

        self.assertTrue(checkpoint_post_display_enabled("all", "state"))
        self.assertTrue(
            checkpoint_post_display_enabled("all", "post_resume_next")
        )
        self.assertFalse(
            checkpoint_post_display_enabled("post-resume-next", "state")
        )
        self.assertTrue(
            checkpoint_post_display_enabled(
                "post-resume-next", "post_resume_next"
            )
        )

    def test_full_state_load_drift_requires_an_input_free_gap(self) -> None:
        from dos_re_harness.remote_capture import (
            full_state_resume_remaining_values,
        )

        self.assertEqual(
            full_state_resume_remaining_values(
                44,
                [40, 80],
                [],
            ),
            [80],
        )
        with self.assertRaisesRegex(ValueError, "missed input event"):
            full_state_resume_remaining_values(
                44,
                [40, 42, 80],
                [(42, True, ["left"])],
            )
        with self.assertRaisesRegex(ValueError, "missed input event"):
            full_state_resume_remaining_values(
                44,
                [40, 42, 80],
                [(40, True, ["left"])],
            )

    def test_running_poke_halts_writes_and_resumes(self) -> None:
        from dos_re_harness.remote_capture import apply_running_poke

        calls = []

        class FakeGdb:
            def halt(self, timeout: float) -> str:
                calls.append(("halt", timeout))
                return "S05"

            def write_memory(self, address: int, data: bytes) -> None:
                calls.append(("write", address, data))

            def continue_nowait(self) -> None:
                calls.append(("continue",))

        self.assertEqual(
            apply_running_poke(FakeGdb(), 0x193F6, b"\x90" * 5, 7.0),
            "S05",
        )
        self.assertEqual(
            calls,
            [
                ("halt", 7.0),
                ("write", 0x193F6, b"\x90" * 5),
                ("continue",),
            ],
        )

    def test_halt_consumes_pending_breakpoint_stop_without_ctrl_c(self) -> None:
        from dos_re_harness.remote_capture import RspClient

        sent = []

        class FakeSocket:
            def sendall(self, payload: bytes) -> None:
                sent.append(payload)

        client = RspClient.__new__(RspClient)
        client.sock = FakeSocket()
        client._recv_packet = lambda timeout=None: "S05"
        with patch(
            "dos_re_harness.remote_capture.select.select",
            return_value=([client.sock], [], []),
        ):
            self.assertEqual(client.halt(4.0), "S05")
        self.assertEqual(sent, [])

    def test_optional_sequence_screenshot_failure_is_nonfatal(self) -> None:
        from dos_re_harness.remote_capture import capture_optional_screenshot

        class FailingQmp:
            def screendump(self) -> bytes:
                raise RuntimeError("transition has no completed screenshot")

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "frame.png"
            error = capture_optional_screenshot(FailingQmp(), path)
            self.assertIn("no completed screenshot", error or "")
            self.assertFalse(path.exists())

    def test_optional_sequence_screenshot_retries_truncated_png(self) -> None:
        from dos_re_harness.remote_capture import capture_optional_screenshot

        valid = b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND"

        class FlakyQmp:
            calls = 0

            def screendump(self) -> bytes:
                self.calls += 1
                return valid[:-4] if self.calls == 1 else valid

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "frame.png"
            qmp = FlakyQmp()
            self.assertIsNone(capture_optional_screenshot(qmp, path))
            self.assertEqual(qmp.calls, 2)
            self.assertEqual(path.read_bytes(), valid)

    def test_optional_screenshot_does_not_promote_backend_side_effect(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import capture_optional_screenshot

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = (
                root
                / "checkpoints"
                / "loop_tick-1150"
                / "remote_runtime_screen.png"
            )
            destination.parent.mkdir(parents=True)

            class SideEffectQmp:
                def screendump(self) -> bytes:
                    (root / "program_000.png").write_bytes(
                        b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND"
                    )
                    raise RuntimeError("Screenshot capture timed out")

            error = capture_optional_screenshot(
                SideEffectQmp(),
                destination,
            )
            self.assertIn(
                "Screenshot capture timed out",
                error or "",
            )
            self.assertFalse(destination.exists())

    def test_targeted_sequence_screenshot_recovers_backend_side_effect(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            capture_targeted_sequence_screenshot,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            destination = root / "vga_sequence" / "frame_0165.png"
            destination.parent.mkdir()

            class SideEffectQmp:
                def screendump(self) -> bytes:
                    (root / "program_000.png").write_bytes(
                        b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND"
                    )
                    raise RuntimeError("Screenshot capture failed")

            error, deferred = capture_targeted_sequence_screenshot(
                SideEffectQmp(),
                destination,
                root,
            )

            self.assertIsNone(error)
            self.assertTrue(deferred)
            self.assertEqual(
                destination.read_bytes(),
                b"\x89PNG\r\n\x1a\n" + b"0" * 12 + b"IEND",
            )

    def test_deferred_checkpoint_screenshots_follow_request_order(self) -> None:
        from dos_re_harness.remote_capture import (
            recover_checkpoint_screenshot_side_effects,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            records = []
            for index, tick in enumerate((1150, 1170)):
                checkpoint = root / "checkpoints" / f"loop_tick-{tick}"
                checkpoint.mkdir(parents=True)
                metadata_path = (
                    checkpoint / "remote_runtime_registers.json"
                )
                metadata_path.write_text(
                    json.dumps(
                        {
                            "screenshot": None,
                            "screenshot_error": "capture timed out",
                            "screenshot_exact_checkpoint": False,
                            "screenshot_deferred_side_effect": False,
                        }
                    ),
                    encoding="utf-8",
                )
                records.append(
                    {
                        "path": str(checkpoint),
                        "screenshot_requested": True,
                    }
                )
                (root / f"program_{index:03d}.png").write_bytes(
                    f"screen-{tick}".encode("ascii")
                )

            recovered = recover_checkpoint_screenshot_side_effects(
                root,
                records,
                set(),
                timeout_seconds=0.0,
            )
            self.assertEqual(recovered, 2)
            for record, tick in zip(records, (1150, 1170)):
                checkpoint = Path(record["path"])
                self.assertEqual(
                    (
                        checkpoint / "remote_runtime_screen.png"
                    ).read_bytes(),
                    f"screen-{tick}".encode("ascii"),
                )
                metadata = json.loads(
                    (
                        checkpoint / "remote_runtime_registers.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    metadata["screenshot_error"],
                    "capture timed out",
                )
                self.assertFalse(
                    metadata["screenshot_exact_checkpoint"]
                )
                self.assertTrue(
                    metadata["screenshot_deferred_side_effect"]
                )
                self.assertEqual(
                    metadata["screenshot"],
                    str(checkpoint / "remote_runtime_screen.png"),
                )

    def test_deferred_screenshot_recovery_preserves_exact_capture(self) -> None:
        from dos_re_harness.remote_capture import (
            recover_checkpoint_screenshot_side_effects,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = root / "checkpoints" / "breakpoint_hit-1"
            checkpoint.mkdir(parents=True)
            screenshot = checkpoint / "remote_runtime_screen.png"
            screenshot.write_bytes(b"exact-screen")
            metadata_path = checkpoint / "remote_runtime_registers.json"
            metadata_path.write_text(
                json.dumps(
                    {
                        "screenshot": str(screenshot),
                        "screenshot_error": None,
                        "screenshot_exact_checkpoint": True,
                        "screenshot_deferred_side_effect": False,
                    }
                ),
                encoding="utf-8",
            )
            record = {
                "path": str(checkpoint),
                "screenshot_requested": True,
                "screenshot": str(screenshot),
                "screenshot_exact_checkpoint": True,
            }
            (root / "program_000.png").write_bytes(b"side-effect")

            recovered = recover_checkpoint_screenshot_side_effects(
                root,
                [record],
                set(),
                timeout_seconds=0.0,
            )

            self.assertEqual(recovered, 0)
            self.assertEqual(screenshot.read_bytes(), b"exact-screen")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            self.assertTrue(metadata["screenshot_exact_checkpoint"])
            self.assertFalse(metadata["screenshot_deferred_side_effect"])

    def test_screenshot_provenance_manifest_records_nonempty_pngs(self) -> None:
        from dos_re_harness.remote_capture import (
            write_screenshot_provenance_manifest,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            checkpoint = root / "checkpoints" / "loop_tick-1"
            checkpoint.mkdir(parents=True)
            png = b"\x89PNG\r\n\x1a\nvalid"
            (checkpoint / "remote_runtime_screen.png").write_bytes(png)
            manifest = write_screenshot_provenance_manifest(
                root,
                [{"path": str(checkpoint), "value": 1}],
            )
            self.assertIsNotNone(manifest)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(document["tick_count"], 1)
            self.assertEqual(document["valid_png_count"], 1)
            self.assertEqual(document["nonempty_count"], 1)

    def test_mzexplode_wsl_command_maps_windows_paths(self) -> None:
        from dos_re_harness.mzexplode import build_mzexplode_command

        command = build_mzexplode_command(
            tool="/opt/mz-explode/bin/mzexplode",
            input_path=Path(r"C:\work\private\GAME.EXE"),
            output_path=Path(r"C:\work\private\.work\GAME.UNPACKED.EXE"),
            wsl_distribution="Ubuntu",
        )
        self.assertEqual(
            command,
            [
                "wsl.exe",
                "--distribution",
                "Ubuntu",
                "--exec",
                "/opt/mz-explode/bin/mzexplode",
                "/mnt/c/work/private/GAME.EXE",
                "/mnt/c/work/private/.work/GAME.UNPACKED.EXE",
            ],
        )

    def test_mzexplode_writes_hashed_evidence_manifest(self) -> None:
        from dos_re_harness.mzexplode import unpack_mz

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "PACKED.EXE"
            output = root / ".work" / "PACKED.UNPACKED.EXE"
            manifest = root / ".work" / "mzexplode.json"
            source.write_bytes(b"MZpacked")

            def fake_run(command: list[str], check: bool) -> object:
                self.assertFalse(check)
                output.parent.mkdir(parents=True, exist_ok=True)
                output.write_bytes(b"MZunpacked")
                return subprocess.CompletedProcess(command, 0)

            with patch(
                "dos_re_harness.mzexplode.subprocess.run",
                side_effect=fake_run,
            ):
                result = unpack_mz(
                    input_path=source,
                    output_path=output,
                    tool=sys.executable,
                    manifest_path=manifest,
                )

            self.assertEqual(result, manifest)
            document = json.loads(manifest.read_text(encoding="utf-8"))
            self.assertEqual(document["operation"], "mzexplode")
            self.assertEqual(
                document["input"]["sha256"],
                hashlib.sha256(b"MZpacked").hexdigest(),
            )
            self.assertEqual(
                document["output"]["sha256"],
                hashlib.sha256(b"MZunpacked").hexdigest(),
            )
            self.assertEqual(document["tool"]["execution"], "native")
            self.assertEqual(document["exit_code"], 0)

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

    def test_streaming_trace_comparison_supports_gzip(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.jsonl.gz"
            native = Path(temporary) / "native.jsonl"
            with gzip.open(original, "wt", encoding="utf-8") as stream:
                stream.write('{"tick": 0}\n{"tick": 1}\n')
            native.write_text('{"tick": 0}\n{"tick": 2}\n', encoding="utf-8")

            with patch.object(Path, "read_text", side_effect=AssertionError("read all")):
                self.assertEqual(compare_jsonl(original, native), (2, (1, {"tick": (1, 2)})))

    def test_streaming_trace_comparison_counts_and_rejects_bad_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            original = Path(temporary) / "original.jsonl"
            native = Path(temporary) / "native.jsonl"
            original.write_text('{"tick": 0}\n\n{"tick": 1}\n', encoding="utf-8")
            native.write_text('{"tick": 0}\n{"tick": 1}\n', encoding="utf-8")
            self.assertEqual(compare_jsonl(original, native), (2, None))

            native.write_text('{"tick": 0}\n', encoding="utf-8")
            self.assertEqual(
                compare_jsonl(original, native),
                (2, (1, {"row": ({"tick": 1}, MISSING_TRACE_VALUE)})),
            )

            native.write_text('{"tick": 0}\n[]\n', encoding="utf-8")
            with self.assertRaisesRegex(ValueError, r"native.jsonl:2: trace row must be an object"):
                compare_jsonl(original, native)


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

    def test_generic_launcher_isolates_remote_debug_ports(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        remote_capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn("[int]$GdbPort = 0", launcher)
        self.assertIn("[int]$QmpPort = 0", launcher)
        self.assertIn("gdbserver port = $gdb_port", launcher)
        self.assertIn("qmpserver port = $qmp_port", launcher)
        self.assertIn('    --gdb-port "$gdb_port"', launcher)
        self.assertIn('    --qmp-port "$qmp_port"', launcher)
        self.assertIn('"remote_ports":', remote_capture)

    def test_generic_launcher_preserves_empty_program_arguments(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('$programArgumentsArg = if ($ProgramArguments.Length -gt 0)', launcher)
        self.assertIn('$ProgramArguments\n    } else {\n        "__none__"', launcher)
        self.assertIn('if [ "$program_arguments" = "__none__" ]; then', launcher)
        self.assertIn("$programArgumentsArg $VgaAddress $VgaWidth $VgaHeight", launcher)

    def test_generic_launcher_force_kills_stale_headless_runtime(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'pkill -9 -f "dosbox-x.*${runtime_name}.conf"',
            launcher,
        )

    def test_generic_launcher_plumbs_post_resume_breakpoint_series(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[string]$PostResumeBreakHitSeries", launcher)
        self.assertIn(
            '--post-resume-break-hit-series "$post_resume_break_hit_series"',
            launcher,
        )

    def test_generic_launcher_plumbs_halt_safe_displaydump(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        controller = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        backend_patch = (
            TOOLKIT_ROOT
            / "backends"
            / "dosbox-x-remotedebug"
            / "dosbox-x-remotedebug.patch"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$CheckpointDisplayDump", launcher)
        self.assertIn(
            "controller_args+=(--checkpoint-displaydump)",
            launcher,
        )
        self.assertIn('"--checkpoint-displaydump"', controller)
        self.assertIn("capture_display=args.checkpoint_displaydump", controller)
        self.assertIn('execute == "displaydump"', backend_patch)
        self.assertIn('"{\\"name\\": \\"displaydump\\"},"', backend_patch)

    def test_generic_launcher_plumbs_non_mutating_post_resume_continue(
        self,
    ) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$PostResumeContinue", launcher)
        self.assertIn(
            'controller_args+=(--post-resume-continue)',
            launcher,
        )

    def test_generic_launcher_scopes_post_display_capture(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(
            '[ValidateSet("all", "post-resume-next")]',
            launcher,
        )
        self.assertIn(
            '--checkpoint-post-display-scope',
            launcher,
        )
        self.assertIn(
            '"$checkpoint_post_display_scope"',
            launcher,
        )

    def test_generic_launcher_plumbs_final_post_display_capture(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        controller = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn('[string]$FinalPostDisplayBreakSegmented = ""', launcher)
        self.assertIn('[string]$FinalPostDisplayPoke = ""', launcher)
        self.assertIn('final_post_display_break_segmented="__none__"', launcher)
        self.assertIn('--final-post-display-break-segmented', launcher)
        self.assertIn('--final-post-display-poke', launcher)
        self.assertIn('--final-post-display-delay', launcher)
        self.assertIn('--final-post-display-value', launcher)
        self.assertIn('--final-post-display-break-segmented', controller)
        self.assertIn('--final-post-display-value', controller)
        self.assertIn('def capture_final_post_display(', controller)

    def test_generic_launcher_plumbs_full_emulator_save_states(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$CheckpointSaveState", launcher)
        self.assertIn("[string]$LoadSaveState", launcher)
        self.assertIn(
            'controller_args+=(--checkpoint-save-state)',
            launcher,
        )
        self.assertIn(
            'controller_args+=(--load-save-state "$load_save_state")',
            launcher,
        )
        self.assertIn("[string]$LoadSaveStateReadyScreen", launcher)
        self.assertIn(
            "--load-save-state-ready-screen "
            '"$load_save_state_ready_screen"',
            launcher,
        )

    def test_generic_launcher_wraps_opt_in_native_video_capture(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$CaptureVideo", launcher)
        self.assertIn('capture_video="${52}"', launcher)
        self.assertIn("DX-CAPTURE /V %s %s", launcher)
        self.assertIn("$captureVideoArg @StartupKey", launcher)

    def test_generic_launcher_plumbs_optional_opl_log_path(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('[string]$OplLogPath = ""', launcher)
        self.assertIn('[string]$OplTickLinear = ""', launcher)
        self.assertIn('DOS_RE_HARNESS_OPL_LOG="$opl_log_path"', launcher)
        self.assertIn('DOS_RE_HARNESS_OPL_TICK_LINEAR="$opl_tick_linear"', launcher)
        self.assertIn(
            "$oplLogPathArg $oplTickLinearArg "
            "$callNearContinueAfterReturnArg $RemoteTimeout "
            "$vgaSequenceScreenshotOnStopArg "
            "$stateInputHookLinearArg $stateInputLinearArg "
            "$StateInputWidth $stateInputLogPathWsl $turboArg "
            "$CheckpointPostDisplayScope $stateInputStopValueArg "
            "$GdbPort $QmpPort "
            "@StartupKey",
            launcher,
        )

    def test_generic_launcher_plumbs_guest_state_input_accelerator(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        backend_patch = (
            TOOLKIT_ROOT
            / "backends"
            / "dosbox-x-remotedebug"
            / "dosbox-x-remotedebug.patch"
        ).read_text(encoding="utf-8")
        self.assertIn('[string]$StateInputHookLinear = ""', launcher)
        self.assertIn('[string]$StateInputLinear = ""', launcher)
        self.assertIn('[ValidateSet(1, 2, 4)]', launcher)
        self.assertIn('[int]$StateInputWidth = 2', launcher)
        self.assertIn('[string]$StateInputLogPath = ""', launcher)
        self.assertIn('[string]$StateInputStopValue = ""', launcher)
        self.assertIn('[switch]$CheckpointDac', launcher)
        self.assertIn('controller_args+=(--checkpoint-dac)', launcher)
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_SCRIPT="$input_script"',
            launcher,
        )
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_HOOK_LINEAR=',
            launcher,
        )
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_LINEAR="$state_input_linear"',
            launcher,
        )
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_WIDTH="$state_input_width"',
            launcher,
        )
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_LOG="$state_input_log_path"',
            launcher,
        )
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_STOP_VALUE="$state_input_stop_value"',
            launcher,
        )
        self.assertIn("QMP_ProcessGuestStateInput", backend_patch)
        self.assertIn(
            "DOS_RE_HARNESS_STATE_INPUT_SCRIPT",
            backend_patch,
        )
        self.assertIn('line == "# state_unwrap=1"', backend_patch)
        self.assertIn("state_epoch_base", backend_patch)

    def test_guest_state_stop_can_run_without_input_script(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        backend_patch = (
            TOOLKIT_ROOT
            / "backends"
            / "dosbox-x-remotedebug"
            / "dosbox-x-remotedebug.patch"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'if [ "$input_script" != "__none__" ]; then', launcher
        )
        self.assertIn(
            "InputScript or StateInputStopValue", launcher
        )
        self.assertIn(
            "StateInputStopValue requires a state-input hook", launcher
        )
        self.assertIn(
            "if (!have_script && !have_stop) return false;",
            backend_patch,
        )

    def test_guest_state_input_bootstraps_initial_held_keys(self) -> None:
        backend_patch = (
            TOOLKIT_ROOT
            / "backends"
            / "dosbox-x-remotedebug"
            / "dosbox-x-remotedebug.patch"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "static std::map<KBD_KEYS, std::string> initial_held;",
            backend_patch,
        )
        self.assertIn(
            "initial_held[key] = qcode;",
            backend_patch,
        )
        self.assertIn(
            "std::map<KBD_KEYS, std::string> held = initial_held;",
            backend_patch,
        )
        self.assertIn(
            "static std::vector<std::pair<KBD_KEYS, std::string>> initial_held_order;",
            backend_patch,
        )
        self.assertIn(
            "for (const auto& item : initial_held_order)",
            backend_patch,
        )
        self.assertIn(
            "SAVESTATE_ConsumeLoadPauseRelease",
            backend_patch,
        )

    def test_state_input_stop_uses_immediate_halted_savestate(self) -> None:
        from dos_re_harness.remote_capture import (
            finalize_halted_state_input_save_state,
        )

        calls = []

        class FakeQmp:
            supports_immediate_savestate = True

            def save_state_immediate(self, path: Path) -> Path:
                calls.append(("save-immediate", path))
                path.write_bytes(b"exact halted machine")
                return path

        class FakeGdb:
            def __getattr__(self, name: str) -> object:
                raise AssertionError(
                    f"immediate state save unexpectedly used GDB {name}"
                )

        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "state_input_stop-42"
            checkpoint.mkdir()
            metadata_path = checkpoint / "remote_runtime_registers.json"
            metadata_path.write_text("{}", encoding="utf-8")
            registers = {"cs": 0x1234, "eip": 0x5678, "ds": 0x2000}
            stop, returned_registers = (
                finalize_halted_state_input_save_state(
                    FakeQmp(),
                    FakeGdb(),
                    {"path": str(checkpoint)},
                    "S05",
                    registers,
                    3.0,
                    lambda observed: {
                        "loop_tick": 42,
                        "ds": observed["ds"],
                    },
                )
            )

            self.assertEqual(stop, "S05")
            self.assertEqual(returned_registers, registers)
            self.assertEqual(calls[0][0], "save-immediate")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            resume = metadata["save_state_resume"]
            self.assertTrue(resume["halted_boundary"])
            self.assertTrue(resume["immediate_halted"])
            self.assertIsNone(resume["breakpoint_linear"])
            self.assertIsNone(resume["single_step_stop"])
            self.assertEqual(resume["post_save_state"]["loop_tick"], 42)
            self.assertEqual(resume["pre_save_registers"], registers)

    def test_breakpoint_checkpoint_uses_immediate_halted_savestate(self) -> None:
        from dos_re_harness.remote_capture import (
            finalize_halted_checkpoint_save_state,
        )

        calls = []

        class FakeQmp:
            supports_immediate_savestate = True

            def save_state_immediate(self, path: Path) -> Path:
                calls.append(("save-immediate", path))
                path.write_bytes(b"exact breakpoint machine")
                return path

        class FakeGdb:
            def __getattr__(self, name: str) -> object:
                raise AssertionError(
                    f"immediate breakpoint save unexpectedly used GDB {name}"
                )

        with tempfile.TemporaryDirectory() as temporary:
            checkpoint = Path(temporary) / "loop_tick-0"
            checkpoint.mkdir()
            metadata_path = checkpoint / "remote_runtime_registers.json"
            metadata_path.write_text("{}", encoding="utf-8")
            registers = {"cs": 0x0824, "eip": 0x850C, "ds": 0x2567}
            stop, returned_registers = (
                finalize_halted_checkpoint_save_state(
                    FakeQmp(),
                    FakeGdb(),
                    0x082402CC,
                    {
                        "path": str(checkpoint),
                        "stop": "S05",
                        "registers": registers,
                    },
                    3.0,
                    lambda observed: {
                        "loop_tick": 0,
                        "ds": observed["ds"],
                    },
                )
            )

            self.assertEqual(stop, "S05")
            self.assertEqual(returned_registers, registers)
            self.assertEqual(calls[0][0], "save-immediate")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            resume = metadata["save_state_resume"]
            self.assertTrue(resume["halted_boundary"])
            self.assertTrue(resume["immediate_halted"])
            self.assertIsNone(resume["single_step_stop"])
            self.assertEqual(resume["post_save_state"]["loop_tick"], 0)
            self.assertEqual(resume["pre_save_registers"], registers)

    def test_backend_documents_guest_state_counter_unwrapping(self) -> None:
        backend_readme = (
            TOOLKIT_ROOT / "backends" / "dosbox-x-remotedebug" / "README.md"
        ).read_text(encoding="utf-8")
        self.assertIn("# state_unwrap=1", backend_readme)
        self.assertIn("counter wraps or", backend_readme)
        self.assertIn("resets to a lower value", backend_readme)

    def test_generic_launcher_exposes_opt_in_turbo_capture(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$Turbo", launcher)
        self.assertIn('turbo="${68}"', launcher)
        self.assertIn('checkpoint_post_display_scope="${69}"', launcher)
        self.assertIn("shift 70", launcher)
        self.assertIn("turbo = $turbo", launcher)
        self.assertIn("stop turbo on key = false", launcher)
        self.assertIn(
            "$StateInputWidth $stateInputLogPathWsl $turboArg "
            "$CheckpointPostDisplayScope $stateInputStopValueArg "
            "$GdbPort $QmpPort "
            "@StartupKey",
            launcher,
        )

    def test_backend_build_defaults_to_incremental_make(self) -> None:
        prepare = (
            TOOLKIT_ROOT / "scripts" / "prepare-wsl-backend.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$Reconfigure", prepare)
        self.assertIn("Reconfigure requires Build", prepare)
        self.assertIn('[ ! -f Makefile ]', prepare)
        self.assertIn("./build-debug --enable-remotedebug", prepare)
        self.assertIn(
            'make --silent --no-print-directory '
            '-j"${DOS_RE_HARNESS_BUILD_JOBS:-3}"',
            prepare,
        )
        self.assertIn(
            'build_log=".dos-re-harness-incremental-build.log"',
            prepare,
        )
        self.assertIn('else cat "$build_log"; exit 1', prepare)
        self.assertIn("$reconfigureArg", prepare)
        self.assertIn("$''\\r''", prepare)

    def test_generic_launcher_can_continue_after_near_call_return(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        controller = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$CallNearContinueAfterReturn", launcher)
        self.assertIn('[string]$CallNearBreakOffset = ""', launcher)
        self.assertIn('"--call-near-break-offset"', launcher)
        self.assertIn(
            "controller_args+=(--call-near-continue-after-return)",
            launcher,
        )
        self.assertIn('"--call-near-continue-after-return"', controller)
        self.assertIn(
            "clear_halted_breakpoint(\n"
            "                    gdb,\n"
            "                    call_near_return_linear,",
            controller,
        )
        self.assertIn('"--call-near-break-offset"', controller)

    def test_post_resume_breakpoint_clears_a_different_state_address(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            should_clear_resume_checkpoint_breakpoint,
        )

        self.assertFalse(
            should_clear_resume_checkpoint_breakpoint(
                0x19DDC, None, (0x1636, 0x3A7C), 1
            )
        )
        self.assertTrue(
            should_clear_resume_checkpoint_breakpoint(
                0x19DDC, None, (0x1636, 0x67AF), 1
            )
        )
        self.assertTrue(
            should_clear_resume_checkpoint_breakpoint(
                0x19DDC, 0x1CB0F, None, 1
            )
        )
        self.assertTrue(
            should_clear_resume_checkpoint_breakpoint(
                0x19DDC, None, (0x1636, 0x3A7C), 2
            )
        )

    def test_state_input_stop_allows_post_resume_breakpoint_series(self) -> None:
        from dos_re_harness import remote_capture

        with tempfile.TemporaryDirectory() as temporary:
            arguments = [
                "remote_capture.py",
                "--out-dir",
                temporary,
                "--state-schema",
                str(FIXTURE_ROOT / "state.schema.json"),
                "--state-input-stop-value",
                "679",
                "--post-resume-break-segmented",
                "0x1111:0x20",
                "--post-resume-break-hit-series",
                "1,3",
            ]
            with (
                patch("sys.argv", arguments),
                patch(
                    "dos_re_harness.remote_capture.RspClient",
                    side_effect=RuntimeError("validation passed"),
                ),
            ):
                with self.assertRaisesRegex(
                    RuntimeError,
                    "validation passed",
                ):
                    remote_capture.main()

    def test_state_handoff_steps_when_breakpoint_was_consumed(self) -> None:
        from dos_re_harness.remote_capture import (
            step_past_optional_halted_breakpoint,
        )

        class FakeGdb:
            def __init__(self) -> None:
                self.stepped = False

            def remove_breakpoint(self, address: int) -> None:
                self.address = address
                raise RuntimeError("breakpoint removal failed: 'E01'")

            def step_nowait(self) -> None:
                self.stepped = True

            def wait_for_stop(self, timeout: float) -> str:
                self.timeout = timeout
                return "S05"

        gdb = FakeGdb()
        self.assertEqual(
            step_past_optional_halted_breakpoint(gdb, 0x19DDC, 7.0),
            "S05",
        )
        self.assertEqual(gdb.address, 0x19DDC)
        self.assertTrue(gdb.stepped)
        self.assertEqual(gdb.timeout, 7.0)

    def test_full_state_resume_advances_checkpoint_instruction(self) -> None:
        from dos_re_harness.remote_capture import (
            prepare_full_state_resume_breakpoint,
        )

        class FakeGdb:
            def __init__(self) -> None:
                self.stepped = False
                self.current = {"eip": 0x12343}

            def remove_breakpoint(self, _address: int) -> None:
                raise RuntimeError("breakpoint removal failed: 'E01'")

            def step_nowait(self) -> None:
                self.stepped = True

            def wait_for_stop(self, _timeout: float) -> str:
                return "S05"

            def registers(self) -> dict[str, int]:
                return self.current

        gdb = FakeGdb()
        registers = prepare_full_state_resume_breakpoint(
            gdb,
            0x12340,
            7.0,
            {"eip": 0x12340},
        )
        self.assertTrue(gdb.stepped)
        self.assertEqual(registers["eip"], 0x12343)

        gdb.stepped = False
        registers = prepare_full_state_resume_breakpoint(
            gdb,
            0x12340,
            7.0,
            {"eip": 0x12343},
        )
        self.assertFalse(gdb.stepped)
        self.assertEqual(registers["eip"], 0x12343)

    def test_generic_launcher_plumbs_remote_operation_timeout(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[double]$RemoteTimeout = 10.0", launcher)
        self.assertIn('remote_timeout="${62}"', launcher)
        self.assertIn('    --timeout "$remote_timeout"', launcher)
        self.assertIn(
            "$callNearContinueAfterReturnArg $RemoteTimeout "
            "$vgaSequenceScreenshotOnStopArg "
            "$stateInputHookLinearArg $stateInputLinearArg "
            "$StateInputWidth $stateInputLogPathWsl $turboArg "
            "$CheckpointPostDisplayScope $stateInputStopValueArg "
            "$GdbPort $QmpPort "
            "@StartupKey",
            launcher,
        )

    def test_vga_sequence_target_requests_only_the_matched_screenshot(
        self,
    ) -> None:
        from dos_re_harness.remote_capture import (
            should_capture_vga_sequence_screenshot,
        )

        target = "ab" * 32
        other = "cd" * 32
        self.assertTrue(
            should_capture_vga_sequence_screenshot(True, False, "", other)
        )
        self.assertFalse(
            should_capture_vga_sequence_screenshot(False, True, target, other)
        )
        self.assertTrue(
            should_capture_vga_sequence_screenshot(False, True, target, target)
        )
        self.assertFalse(
            should_capture_vga_sequence_screenshot(False, True, "", target)
        )
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$VgaSequenceScreenshotOnStop", launcher)
        self.assertIn("[switch]$VgaSequenceScreenshotAll", launcher)
        self.assertIn('vga_sequence_screenshot_on_stop="${63}"', launcher)
        self.assertIn("shift 70", launcher)
        self.assertIn(
            "controller_args+=(--vga-sequence-screenshot-on-stop)",
            launcher,
        )
        self.assertIn(
            "controller_args+=(--vga-sequence-screenshot-all)",
            launcher,
        )

    def test_display_sequence_writes_completed_frame_and_dac(self) -> None:
        from dos_re_harness.remote_capture import (
            write_display_dac_sequence_sample,
        )

        display = {
            "data": bytes(range(24)),
            "width": 3,
            "height": 2,
            "bpp": 32,
            "pitch": 12,
            "generation": 17,
        }
        dac = {
            "data": bytes(256 * 3),
            "bits": 6,
            "pel_mask": 255,
            "pel_index": 0,
            "state": 1,
            "write_index": 0,
            "read_index": 255,
            "first_changed": 256,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sample = write_display_dac_sequence_sample(
                root,
                4,
                display,
                dac,
            )

            self.assertEqual(
                (root / "frame_0004.display.bin").read_bytes(),
                display["data"],
            )
            self.assertEqual(
                (root / "frame_0004.dac.bin").read_bytes(),
                dac["data"],
            )
            self.assertEqual(sample["display"]["generation"], 17)
            self.assertEqual(sample["display"]["width"], 3)
            self.assertEqual(sample["display"]["height"], 2)
            self.assertEqual(sample["display"]["pitch"], 12)
            self.assertEqual(sample["display"]["size"], 24)

    def test_generic_launcher_plumbs_running_display_sequence(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[int]$DisplaySequenceFrames = 0", launcher)
        self.assertIn("[double]$DisplaySequenceInterval", launcher)
        self.assertIn(
            'controller_args+=(--display-sequence-frames "$display_sequence_frames")',
            launcher,
        )
        self.assertIn(
            'controller_args+=(--display-sequence-interval "$display_sequence_interval")',
            launcher,
        )

    def test_generic_launcher_plumbs_post_resume_display_history(self) -> None:
        launcher = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        controller = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        backend_patch = (
            TOOLKIT_ROOT
            / "backends"
            / "dosbox-x-remotedebug"
            / "dosbox-x-remotedebug.patch"
        ).read_text(encoding="utf-8")

        self.assertIn(
            "[int]$PostResumeDisplayHistoryCapacity = 0",
            launcher,
        )
        self.assertIn(
            'controller_args+=(\n'
            '        --post-resume-display-history-capacity',
            launcher,
        )
        self.assertIn(
            '"--post-resume-display-history-capacity"',
            controller,
        )
        self.assertIn('execute == "displayhistory-start"', backend_patch)
        self.assertIn('execute == "displayhistory-stop"', backend_patch)
        self.assertIn('\\"palette_size\\"', backend_patch)

    def test_ghidra_query_supports_atomic_custom_evidence(self) -> None:
        wrapper = (
            TOOLKIT_ROOT / "scripts" / "ghidra-query.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('"custom"', wrapper)
        self.assertIn("[string]$CustomScript", wrapper)
        self.assertIn("[string[]]$AdditionalScriptPath", wrapper)
        self.assertIn("[switch]$NoAnalysis", wrapper)
        self.assertIn('$temporaryOutput = "$resolvedOutput.partial"', wrapper)
        self.assertIn("Refusing to overwrite Ghidra evidence", wrapper)

    def test_ghidra_query_keeps_multiple_script_paths_separate(self) -> None:
        wrapper = (
            TOOLKIT_ROOT / "scripts" / "ghidra-query.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "[System.Collections.Generic.List[string]]::new()",
            wrapper,
        )
        self.assertIn("$scriptPaths.Add($genericScriptPath)", wrapper)
        self.assertIn("$scriptPaths.Add((Resolve-Path $path).Path)", wrapper)
        self.assertIn(
            "$scriptPath = $scriptPaths -join [IO.Path]::PathSeparator",
            wrapper,
        )
        self.assertIn("if ([IO.Path]::PathSeparator -eq ';')", wrapper)
        self.assertIn("$scriptPath = '\"' + $scriptPath + '\"'", wrapper)

    def test_backend_patch_preserves_upstream_line_endings(self) -> None:
        attributes = (TOOLKIT_ROOT / ".gitattributes").read_text()
        self.assertIn("*.patch -text", attributes.splitlines())
        backend = TOOLKIT_ROOT / "backends" / "dosbox-x-remotedebug"
        patch_bytes = (backend / "dosbox-x-remotedebug.patch").read_bytes()
        # The pinned upstream save-state source uses CRLF, including hunk
        # context. Git must preserve those bytes on every host.
        section = patch_bytes.split(
            b"diff --git a/src/misc/savestates.cpp b/src/misc/savestates.cpp\n",
            1,
        )[1]
        for line in section.splitlines(keepends=True):
            if line.startswith((b"---", b"+++")):
                continue
            if line.startswith((b" ", b"+", b"-")):
                self.assertTrue(line.endswith(b"\r\n"), repr(line))

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
                "4784225ddfeae06a4042aeefff0518005eabfb4de6733554e5dd45fb2795e36f",
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

    def test_evidence_manifest_hashes_movie_override(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            override = root / "generated.movie.json"
            override.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "actions": ["breakstate:0x850c:loop_tick==183:245"],
                    }
                ),
                encoding="utf-8",
            )
            manifest_path = write_evidence_manifest(
                project,
                "boot",
                root / "capture",
                ["capture", "boot"],
                0,
                input_movie_path=override,
            )
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            contract = document["contracts"]["input_movie"]
            self.assertEqual(Path(contract["path"]), override.resolve())
            self.assertEqual(
                contract["sha256"],
                hashlib.sha256(override.read_bytes()).hexdigest(),
            )

    def test_evidence_manifest_hashes_state_input_script(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            script = root / "generated.input.script"
            script.write_text(
                "dos-re-state-input-script-v1\n"
                "42=down.left\n"
                "47=up.left\n",
                encoding="utf-8",
            )
            manifest_path = write_evidence_manifest(
                project,
                "boot",
                root / "capture",
                ["capture", "boot"],
                0,
                input_script_path=script,
            )
            document = json.loads(manifest_path.read_text(encoding="utf-8"))
            contract = document["contracts"]["state_input_script"]
            self.assertEqual(Path(contract["path"]), script.resolve())
            self.assertEqual(
                contract["sha256"],
                hashlib.sha256(script.read_bytes()).hexdigest(),
            )

    def test_evidence_manifest_hashes_nested_checkpoint_artifacts(self) -> None:
        project = load_project(FIXTURE_ROOT / "project.json")
        with tempfile.TemporaryDirectory() as temporary:
            out_dir = Path(temporary)
            checkpoint = out_dir / "checkpoints" / "loop_tick-183"
            checkpoint.mkdir(parents=True)
            artifact = checkpoint / "remote_runtime_ds.bin"
            artifact.write_bytes(b"checkpoint")
            manifest_path = write_evidence_manifest(
                project,
                "boot",
                out_dir,
                ["capture", "boot"],
                0,
            )
            document = json.loads(
                manifest_path.read_text(encoding="utf-8")
            )
            records = {
                item["path"]: item for item in document["artifacts"]
            }
            self.assertEqual(
                records[
                    "checkpoints/loop_tick-183/remote_runtime_ds.bin"
                ]["sha256"],
                hashlib.sha256(b"checkpoint").hexdigest(),
            )

    def test_capture_summary_replaces_large_embedded_records_with_hashes(
        self,
    ) -> None:
        from dos_re_harness.capture_summary import (
            build_capture_summary,
            format_capture_summary_line,
            write_capture_summary,
        )

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            dump = capture / "remote_runtime_ds.bin"
            dump.write_bytes(b"captured-state")
            input_events = [
                {
                    "value": value,
                    "pressed": value % 2 == 0,
                    "qcodes": ["left", "spc"],
                }
                for value in range(100)
            ]
            registers = {
                "stop": "T05",
                "registers": {
                    "cs": 0x1000,
                    "eip": 0x12345,
                    "ds": 0x2000,
                    "ss": 0x2000,
                    "esp": 0xFF00,
                },
                "dump": str(dump),
                "dump_size": dump.stat().st_size,
                "break_state": {
                    "matched_hit": 85,
                    "state": {"loop_tick": 327},
                    "input_script_source": "route.input.script",
                    "input_script": input_events,
                },
                "state_checkpoints": [
                    {
                        "field": "loop_tick",
                        "value": 327,
                        "matched_hit": 327,
                        "state": {
                            "loop_tick": 327,
                            "large_transient": list(range(100)),
                        },
                        "path": str(capture / "checkpoints" / "loop_tick-327"),
                    }
                ],
            }
            (capture / "remote_runtime_registers.json").write_text(
                json.dumps(registers),
                encoding="utf-8",
            )

            summary = build_capture_summary(capture)
            compact_break = summary["break_state"]
            self.assertNotIn("input_script", compact_break)
            self.assertEqual(compact_break["input_script_event_count"], 100)
            self.assertEqual(len(compact_break["input_script_sha256"]), 64)
            checkpoint = summary["state_checkpoints"][0]
            self.assertNotIn("state", checkpoint)
            self.assertEqual(checkpoint["state_field_count"], 2)
            self.assertEqual(len(checkpoint["state_sha256"]), 64)
            self.assertEqual(summary["artifacts"][0]["path"], "remote_runtime_ds.bin")
            self.assertEqual(
                format_capture_summary_line(summary),
                (
                    "CAPTURE stop=T05 cs=1000 eip=00012345 "
                    "state_checkpoints=1 post_resume_hits=0"
                ),
            )

            output = write_capture_summary(capture)
            self.assertEqual(output, capture / "capture_summary.json")
            written = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(written, summary)


class AudioEvidenceTests(unittest.TestCase):
    @staticmethod
    def _write_wave(
        path: Path,
        channels: int,
        frames: list[tuple[int, ...]],
        sample_rate: int = 8000,
    ) -> None:
        with wave.open(str(path), "wb") as output:
            output.setnchannels(channels)
            output.setsampwidth(2)
            output.setframerate(sample_rate)
            output.writeframes(
                b"".join(
                    struct.pack("<" + "h" * channels, *frame)
                    for frame in frames
                )
            )

    def test_wave_summary_reports_reproducible_pcm_metrics(self) -> None:
        from dos_re_harness.audio import summarize_wave

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "capture.wav"
            self._write_wave(
                path,
                2,
                [(0, 0), (100, -100), (-200, 200), (300, -300)],
            )
            summary = summarize_wave(path)
            self.assertEqual(summary["channels"], 2)
            self.assertEqual(summary["sample_rate"], 8000)
            self.assertEqual(summary["sample_width_bits"], 16)
            self.assertEqual(summary["frame_count"], 4)
            self.assertEqual(summary["peak"], 300)
            self.assertAlmostEqual(summary["duration_seconds"], 0.0005)
            self.assertEqual(len(summary["sha256"]), 64)
            self.assertEqual(summary["channel_metrics"][0]["minimum"], -200)
            self.assertEqual(summary["channel_metrics"][1]["maximum"], 200)

    def test_wave_comparison_supports_tolerance_and_stereo_mixdown(self) -> None:
        from dos_re_harness.audio import compare_waves

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.wav"
            rewrite = root / "rewrite.wav"
            self._write_wave(
                original,
                2,
                [(100, 100), (200, 200), (-300, -300), (0, 0)],
            )
            self._write_wave(
                rewrite,
                1,
                [(101,), (198,), (-300,), (0,)],
            )
            result = compare_waves(
                original,
                rewrite,
                mixdown=True,
                sample_tolerance=2,
            )
            self.assertTrue(result["formats_compatible"])
            self.assertEqual(result["compared_frames"], 4)
            self.assertEqual(result["different_samples"], 0)
            self.assertEqual(result["maximum_absolute_error"], 2)
            self.assertIsNone(result["first_different_frame"])

    def test_capture_summary_includes_wave_artifacts_and_metrics(self) -> None:
        from dos_re_harness.capture_summary import build_capture_summary

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            (capture / "remote_runtime_registers.json").write_text(
                json.dumps(
                    {
                        "stop": "T05",
                        "registers": {"cs": 0, "eip": 0},
                    }
                ),
                encoding="utf-8",
            )
            self._write_wave(capture / "program_000.wav", 1, [(1,), (-1,)])
            summary = build_capture_summary(capture)
            self.assertEqual(summary["counts"]["wave_files"], 1)
            self.assertEqual(summary["audio"][0]["path"], "program_000.wav")
            self.assertEqual(summary["audio"][0]["peak"], 1)

    def test_simple_actions_return_final_wave_capture_state(self) -> None:
        from dos_re_harness.remote_capture import run_simple_key_actions

        class FakeQmp:
            def __init__(self) -> None:
                self.capture_operations: list[bool] = []

            def capture_wave(self, start: bool) -> None:
                self.capture_operations.append(start)

        qmp = FakeQmp()
        active = run_simple_key_actions(
            qmp,
            ["capture-wave:start", "capture-wave:stop", "capture-wave:start"],
        )
        self.assertTrue(active)
        self.assertEqual(qmp.capture_operations, [True, False, True])

        active = run_simple_key_actions(
            qmp,
            ["capture-wave:stop"],
            active,
        )
        self.assertFalse(active)
        self.assertEqual(qmp.capture_operations[-1], False)

    def test_simple_actions_support_explicit_key_transitions(self) -> None:
        from dos_re_harness.remote_capture import run_simple_key_actions

        class FakeQmp:
            def __init__(self) -> None:
                self.key_operations: list[tuple[str, bool]] = []

            def key_event(self, qcode: str, down: bool) -> None:
                self.key_operations.append((qcode, down))

        qmp = FakeQmp()
        run_simple_key_actions(qmp, ["keydown:up", "keydown:spc", "keyup:spc"])
        self.assertEqual(
            qmp.key_operations,
            [("up", True), ("spc", True), ("spc", False)],
        )

    def test_simple_actions_can_remove_loaded_state_breakpoint(self) -> None:
        from dos_re_harness.remote_capture import run_simple_key_actions

        class FakeQmp:
            pass

        class FakeGdb:
            def __init__(self) -> None:
                self.removed: list[int] = []

            def remove_breakpoint(self, address: int) -> None:
                self.removed.append(address)

        gdb = FakeGdb()
        run_simple_key_actions(
            FakeQmp(),
            ["removebreak:0x850c"],
            gdb=gdb,
        )
        self.assertEqual(gdb.removed, [0x850C])

    def test_simple_actions_restore_serialized_breakpoint_byte_when_untracked(self) -> None:
        from dos_re_harness.remote_capture import run_simple_key_actions

        class FakeQmp:
            pass

        class FakeGdb:
            def remove_breakpoint(self, address: int) -> None:
                raise RuntimeError("untracked breakpoint")

            def read_memory(self, address: int, length: int) -> bytes:
                self.read = (address, length)
                return b"\xcc"

            def write_memory(self, address: int, data: bytes) -> None:
                self.write = (address, data)

        gdb = FakeGdb()
        run_simple_key_actions(
            FakeQmp(),
            ["removebreak:0x850c:83"],
            gdb=gdb,
        )
        self.assertEqual(gdb.read, (0x850C, 1))
        self.assertEqual(gdb.write, (0x850C, b"\x83"))

    def test_restored_post_keys_release_synthetic_stop_for_wait_state(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        marker = "if wait_predicates:\n                    # A restored state starts"
        self.assertIn(marker, capture)

    def test_post_restore_actions_enter_restore_setup_without_other_mutation(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "or args.post_restore_key\n        ):\n            stop, regs = prepare_restore_halt",
            capture,
        )

    def test_resume_checkpoint_applies_post_restore_actions_after_script_keys(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn(
            "if args.halt_after_poke or args.post_restore_key:",
            capture,
        )
        self.assertNotIn(
            "if args.post_restore_key:\n"
            "                        wave_capture_active = run_simple_key_actions(\n"
            "                            qmp_resume,\n"
            "                            args.post_restore_key,\n"
            "                            wave_capture_active,\n"
            "                            gdb,\n"
            "                        )\n"
            "                    restored_regs = gdb.registers()",
            capture,
        )
        self.assertIn(
            "remaining_values = observed_values[1:]\n"
            "                    if args.post_restore_key:\n"
            "                        wave_capture_active = run_simple_key_actions(\n"
            "                            qmp_resume,\n"
            "                            args.post_restore_key,\n"
            "                            wave_capture_active,\n"
            "                            gdb,\n"
            "                        )\n"
            "                    if not remaining_values:",
            capture,
        )

    def test_side_breakpoint_pokes_apply_before_state_capture(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"--state-side-break-poke",', capture)
        self.assertIn(
            "side_writes = apply_halted_pokes(\n"
            "                            gdb,\n"
            "                            args.state_side_break_poke,\n"
            "                            side_registers,\n"
            "                        )\n"
            "                        side_state = read_resumed_checkpoint_state(",
            capture,
        )
        self.assertIn('"writes": side_writes,', capture)

        wrapper = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('[string[]]$ResumeSideBreakPoke = @(),', wrapper)
        self.assertIn('--state-side-break-poke "$poke"', wrapper)

    def test_startup_writehalted_preserves_the_debugger_stop(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn('if key.startswith("writehalted:"):', capture)
        self.assertIn(
            "gdb.write_memory_chunked(linear_address, data)\n"
            "                        halted_regs = gdb.registers()\n"
            "                        print(\n"
            "                            f\"wrote {len(data)} halted bytes",
            capture,
        )

    def test_backend_owned_resumed_input_does_not_duplicate_qmp_events(self) -> None:
        from dos_re_harness.remote_capture import replay_resumed_script_transition

        class FakeQmp:
            def __init__(self) -> None:
                self.key_operations: list[tuple[str, bool]] = []

            def key_event(self, qcode: str, down: bool) -> None:
                self.key_operations.append((qcode, down))

        events = [
            (719, True, ["left"]),
            (727, False, ["left"]),
        ]
        qmp = FakeQmp()
        self.assertEqual(
            replay_resumed_script_transition(qmp, events, 727, "backend"),
            [],
        )
        self.assertEqual(qmp.key_operations, [])

        self.assertEqual(
            replay_resumed_script_transition(qmp, events, 727, "controller"),
            [("left", False)],
        )
        self.assertEqual(qmp.key_operations, [("left", False)])

        wrapper = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'controller_args+=(--resume-script-event-owner backend)',
            wrapper,
        )

    def test_state_input_observe_only_leaves_script_events_to_controller(self) -> None:
        wrapper = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn("[switch]$StateInputObserveOnly,", wrapper)
        self.assertIn('state_input_observe_only="1"', wrapper)
        self.assertIn(
            'if [ "$state_input_observe_only" != "1" ]; then',
            wrapper,
        )
        self.assertIn(
            'runtime_env+=(DOS_RE_HARNESS_STATE_INPUT_SCRIPT="$input_script")',
            wrapper,
        )
        self.assertIn(
            'controller_args+=(--resume-script-event-owner controller)',
            wrapper,
        )

    def test_backend_input_script_can_end_before_controller_script(self) -> None:
        wrapper = (
            TOOLKIT_ROOT / "scripts" / "run-wsl-remotedebug.ps1"
        ).read_text(encoding="utf-8")
        self.assertIn('[string]$BackendInputScript = "",', wrapper)
        self.assertIn('backend_input_script="__same__"', wrapper)
        self.assertIn(
            'DOS_RE_HARNESS_STATE_INPUT_SCRIPT="$backend_input_script"',
            wrapper,
        )
        self.assertIn(
            'if [ "$backend_input_script" != "__same__" ]; then\n'
            '            controller_args+=(--resume-script-event-owner controller)',
            wrapper,
        )

    def test_loaded_state_continue_allows_wait_state_to_own_boundary(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'if wait_predicates:\n                        halted_stop = None',
            capture,
        )
        self.assertIn(
            '"loaded full state for wait-state polling",',
            capture,
        )

    def test_paused_load_without_continue_preserves_qmp_hold(self) -> None:
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'args.load_save_state_paused\n                    and not args.load_save_state_continue',
            capture,
        )

    def test_paused_load_with_resume_checkpoint_defers_qmp_release(self) -> None:
        from dos_re_harness.remote_capture import (
            should_defer_paused_load_release,
        )

        self.assertTrue(
            should_defer_paused_load_release(
                paused=True,
                continue_after_load=False,
                has_edits=True,
                has_resume_checkpoint=True,
            )
        )
        self.assertFalse(
            should_defer_paused_load_release(
                paused=True,
                continue_after_load=False,
                has_edits=True,
                has_resume_checkpoint=False,
            )
        )
        capture = (
            TOOLKIT_ROOT / "src" / "dos_re_harness" / "remote_capture.py"
        ).read_text(encoding="utf-8")
        resume_branch = capture.index("elif args.resume_checkpoint_script:")
        release = capture.index(
            "if defer_loaded_state_resume:", resume_branch
        )
        second_qmp_client = capture.index(
            "qmp_resume = QmpClient(", resume_branch
        )
        self.assertLess(release, second_qmp_client)

    def test_wave_finalization_rejects_placeholder_header(self) -> None:
        from dos_re_harness.remote_capture import wave_file_is_finalized

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            finalized = root / "finalized.wav"
            placeholder = root / "placeholder.wav"
            self._write_wave(finalized, 2, [(1, -1), (2, -2)])
            payload = finalized.read_bytes()
            placeholder.write_bytes(
                payload[:4]
                + (28).to_bytes(4, "little")
                + payload[8:40]
                + bytes(4)
                + payload[44:]
            )

            self.assertTrue(wave_file_is_finalized(finalized))
            self.assertFalse(wave_file_is_finalized(placeholder))


class RegisterWriteTraceTests(unittest.TestCase):
    def test_breakpoint_series_becomes_stable_register_pair_stream(self) -> None:
        from dos_re_harness.write_trace import extract_register_pair_trace

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            for hit, address, value in ((2, 0x1BD, 0x100), (7, 0xA0, 0x57)):
                checkpoint = (
                    capture / "checkpoints" / f"breakpoint_hit-{hit}"
                )
                checkpoint.mkdir(parents=True)
                (checkpoint / "remote_runtime_registers.json").write_text(
                    json.dumps(
                        {
                            "registers": {
                                "ebx": address,
                                "ecx": value,
                                "cs": 0x1234,
                                "eip": 0x5678,
                            }
                        }
                    ),
                    encoding="utf-8",
                )
            result = extract_register_pair_trace(
                capture,
                address_register="ebx",
                value_register="ecx",
                address_mask=0xFF,
                value_mask=0xFF,
            )
            self.assertEqual(
                result["writes"],
                [
                    {"hit": 2, "address": 0xBD, "value": 0},
                    {"hit": 7, "address": 0xA0, "value": 0x57},
                ],
            )
            self.assertEqual(result["write_count"], 2)
            self.assertEqual(len(result["stream_sha256"]), 64)


class CheckpointSeriesTests(unittest.TestCase):
    def test_expected_hit_list_is_positive_strict_and_complete(self) -> None:
        from argparse import ArgumentTypeError

        from dos_re_harness.cli import _parse_hit_list

        self.assertEqual(_parse_hit_list("1,2,0x10"), [1, 2, 16])
        for invalid in ("", "0,2", "1,,2", "2,2", "2,1", "one"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ArgumentTypeError):
                    _parse_hit_list(invalid)

    def test_startup_breakpoint_series_declares_hits(self) -> None:
        from dos_re_harness.checkpoint_series import index_checkpoint_series

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            for hit in (1, 2):
                checkpoint = capture / "checkpoints" / f"breakpoint_hit-{hit}"
                checkpoint.mkdir(parents=True)
                (checkpoint / "memory.bin").write_bytes(bytes([hit]))
            (capture / "capture_summary.json").write_text(
                json.dumps(
                    {
                        "break_state": {
                            "startup_breakpoint_series": {"hits": [1, 2]}
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = index_checkpoint_series(capture, artifact="memory.bin")

            self.assertEqual(result["declared_hits"], [1, 2])
            self.assertEqual(result["hits"], [1, 2])

    def test_expected_hit_count_requires_contiguous_one_based_series(self) -> None:
        from dos_re_harness.checkpoint_series import index_checkpoint_series

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            for hit in (1, 2):
                checkpoint = capture / "checkpoints" / f"breakpoint_hit-{hit}"
                checkpoint.mkdir(parents=True)
                (checkpoint / "memory.bin").write_bytes(bytes([hit]))

            result = index_checkpoint_series(
                capture,
                artifact="memory.bin",
                expected_hit_count=2,
            )
            self.assertEqual(result["hits"], [1, 2])
            self.assertEqual(result["expected_hit_count"], 2)

            with self.assertRaisesRegex(ValueError, "positive"):
                index_checkpoint_series(
                    capture,
                    artifact="memory.bin",
                    expected_hit_count=0,
                )

    def test_checkpoint_artifact_slices_and_registers_are_indexed(self) -> None:
        from dos_re_harness.checkpoint_series import index_checkpoint_series

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            checkpoints = capture / "checkpoints"
            for hit, payload, cs in (
                (2, b"abcdef", 0x1234),
                (7, b"uvwxyz", 0x5678),
            ):
                checkpoint = checkpoints / f"breakpoint_hit-{hit}"
                checkpoint.mkdir(parents=True)
                (checkpoint / "memory.bin").write_bytes(payload)
                (checkpoint / "remote_runtime_registers.json").write_text(
                    json.dumps({"registers": {"cs": cs, "eip": hit}}),
                    encoding="utf-8",
                )
            (capture / "capture_summary.json").write_text(
                json.dumps(
                    {
                        "break_state": {
                            "post_resume_breakpoint_series": {"hits": [2, 7]}
                        }
                    }
                ),
                encoding="utf-8",
            )

            result = index_checkpoint_series(
                capture,
                artifact="memory.bin",
                offset=1,
                length=3,
                registers=["cs", "eip"],
            )

            self.assertEqual(result["hits"], [2, 7])
            self.assertEqual(result["declared_hits"], [2, 7])
            self.assertEqual(result["hit_count"], 2)
            self.assertEqual(len(result["series_sha256"]), 64)
            self.assertEqual(
                result["checkpoints"][0]["slice"]["sha256"],
                hashlib.sha256(b"bcd").hexdigest(),
            )
            self.assertEqual(
                result["checkpoints"][1]["registers"],
                {"cs": 0x5678, "eip": 7},
            )

    def test_checkpoint_index_rejects_declared_hit_and_slice_mismatch(self) -> None:
        from dos_re_harness.checkpoint_series import index_checkpoint_series

        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            checkpoint = capture / "checkpoints" / "breakpoint_hit-2"
            checkpoint.mkdir(parents=True)
            (checkpoint / "memory.bin").write_bytes(b"abc")
            (capture / "capture_summary.json").write_text(
                json.dumps(
                    {
                        "break_state": {
                            "post_resume_breakpoint_series": {"hits": [2, 7]}
                        }
                    }
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "do not match expected"):
                index_checkpoint_series(capture, artifact="memory.bin")

            (capture / "capture_summary.json").unlink()
            with self.assertRaisesRegex(ValueError, "exceeds artifact size"):
                index_checkpoint_series(
                    capture,
                    artifact="memory.bin",
                    offset=2,
                    length=2,
                )


if __name__ == "__main__":
    unittest.main()
