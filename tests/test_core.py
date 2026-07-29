from __future__ import annotations

import json
import hashlib
import struct
import subprocess
import sys
import tempfile
import unittest
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
    first_trace_difference,
    load_jsonl,
)


class CaptureAdapterTests(unittest.TestCase):
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

    def test_rsp_linear_breakpoint_uses_gdb_software_packet(self) -> None:
        from dos_re_harness.remote_capture import RspClient

        client = RspClient.__new__(RspClient)
        packets = []
        client.packet = lambda payload: packets.append(payload) or "OK"
        client.insert_breakpoint(0x4A05C)
        self.assertEqual(packets, ["Z0,4a05c,1"])

    def test_rsp_segmented_breakpoint_packs_backend_address(self) -> None:
        from dos_re_harness.remote_capture import (
            RspClient,
            parse_segmented_nth_breakpoint_action,
            pack_segment_offset,
        )

        self.assertEqual(pack_segment_offset(0x0824, 0x01A5), 0x082401A5)
        self.assertEqual(
            parse_segmented_nth_breakpoint_action(
                "breaksonth:0x0824:0xb39e:14"
            ),
            (0x0824B39E, 14),
        )
        with self.assertRaises(ValueError):
            parse_segmented_nth_breakpoint_action(
                "breaksonth:0x0824:0xb39e:0"
            )
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

    def test_state_checkpoint_writes_complete_nested_snapshot(self) -> None:
        from dos_re_harness.remote_capture import write_state_checkpoint

        class FakeQmp:
            def memdump(self, address: int, size: int) -> bytes:
                return bytes([address & 0xFF]) * size

            def screendump(self) -> bytes:
                return b"checkpoint-screen"

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
                b"checkpoint-screen",
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
            self.assertIsNone(registers["screenshot_error"])
            self.assertTrue(registers["screenshot_exact_checkpoint"])
            self.assertFalse(registers["screenshot_deferred_side_effect"])

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
                        b"backend-screen"
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


if __name__ == "__main__":
    unittest.main()
