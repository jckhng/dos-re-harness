from __future__ import annotations

import contextlib
import ast
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from dos_re_harness import remote_capture
from dos_re_harness.capture_summary import build_capture_summary
from dos_re_harness.checkpoint_series import index_checkpoint_series


ENTRY_ADDRESS = 0x12340020
RETURN_ADDRESS = 0x12340023
ENTRY_EIP = 0x12360
RETURN_EIP = 0x12363
MIDDLE_ADDRESS = 0x12340021
MIDDLE_EIP = 0x12361
SIDE_ADDRESS = 0x43210030
SIDE_EIP = 0x43240


class FakeGdb:
    def __init__(self, stops: list[int]) -> None:
        self.stops = iter(stops)
        self.armed: set[int] = set()
        self.calls: list[tuple] = []
        self.eip = 0
        self.stepping = False
        self.step_eips = iter(())
        self.stop_packet = "T05"

    def insert_breakpoint(self, address: int) -> None:
        self.calls.append(("insert", address))
        self.armed.add(address)

    def remove_breakpoint(self, address: int) -> None:
        self.calls.append(("remove", address))
        self.armed.remove(address)

    def continue_nowait(self) -> None:
        self.calls.append(("continue", tuple(sorted(self.armed))))
        self.stepping = False

    def step_nowait(self) -> None:
        self.calls.append(("step",))
        self.stepping = True

    def wait_for_stop(self, timeout: float) -> str:
        self.calls.append(("wait", timeout))
        if not self.stepping:
            self.eip = next(self.stops)
        else:
            self.eip = next(self.step_eips, self.eip)
        return self.stop_packet

    def registers(self) -> dict[str, int]:
        return {"eip": self.eip, "cs": 0x1234}


class PairedBreakpointTests(unittest.TestCase):
    def run_pairs(self, client: FakeGdb, hits: list[int], capture, **boundaries):
        return remote_capture.stop_on_post_resume_paired_breakpoint_series(
            client,
            entry_address=ENTRY_ADDRESS,
            entry_eip=ENTRY_EIP,
            return_address=RETURN_ADDRESS,
            return_eip=RETURN_EIP,
            hit_counts=hits,
            timeout=7.0,
            capture_boundary=capture,
            **boundaries,
        )

    def run_triplets(self, client: FakeGdb, hits: list[int], capture):
        return self.run_pairs(client, hits, capture,
                              middle_address=MIDDLE_ADDRESS, middle_eip=MIDDLE_EIP)

    def test_side_trace_is_bounded_by_requested_pairs(self) -> None:
        client = FakeGdb([ENTRY_EIP, ENTRY_EIP, SIDE_EIP, SIDE_EIP, RETURN_EIP,
                          ENTRY_EIP, SIDE_EIP, RETURN_EIP])
        sides = []
        captures = []
        self.run_pairs(client, [2, 3], lambda field, hit, *_: captures.append((field, hit)),
                       side_address=SIDE_ADDRESS, side_eip=SIDE_EIP, side_max_hits=8,
                       capture_side=lambda pair, hit, stop, regs: sides.append((pair, hit, regs["eip"])))
        self.assertEqual(sides, [(2, 1, SIDE_EIP), (2, 2, SIDE_EIP), (3, 3, SIDE_EIP)])
        self.assertEqual(captures, [("paired_entry_hit", 2), ("paired_return_hit", 2),
                                    ("paired_entry_hit", 3), ("paired_return_hit", 3)])
        self.assertEqual(client.armed, {RETURN_ADDRESS})
        for call in client.calls:
            if call[0] == "continue" and ENTRY_ADDRESS in call[1]:
                self.assertNotIn(SIDE_ADDRESS, call[1])

    def test_side_at_entry_step_and_cap_preserve_return(self) -> None:
        client = FakeGdb([ENTRY_EIP, RETURN_EIP])
        client.step_eips = iter([SIDE_EIP])
        sides = []
        self.run_pairs(client, [1], lambda *_: None,
                       side_address=SIDE_ADDRESS, side_eip=SIDE_EIP, side_max_hits=1,
                       capture_side=lambda *record: sides.append(record))
        self.assertEqual(len(sides), 1)
        self.assertEqual(client.armed, {RETURN_ADDRESS})

    def test_side_failure_cleans_return_and_side_guards(self) -> None:
        client = FakeGdb([ENTRY_EIP, SIDE_EIP])
        def fail_side(*_):
            raise RuntimeError("side capture failed")
        with self.assertRaisesRegex(RuntimeError, "side capture failed"):
            self.run_pairs(client, [1], lambda *_: None, side_address=SIDE_ADDRESS,
                           side_eip=SIDE_EIP, side_max_hits=8, capture_side=fail_side)
        self.assertEqual(client.armed, set())

    def test_side_step_reaching_return_does_not_continue_past_it(self) -> None:
        client = FakeGdb([ENTRY_EIP, SIDE_EIP])
        client.step_eips = iter([ENTRY_EIP + 1, RETURN_EIP])
        self.run_pairs(client, [1], lambda *_: None, side_address=SIDE_ADDRESS,
                       side_eip=SIDE_EIP, capture_side=lambda *_: None)
        self.assertEqual(client.eip, RETURN_EIP)
        self.assertEqual(sum(call[0] == "continue" for call in client.calls), 2)

    def test_capped_side_trace_is_not_rearmed_for_later_pairs(self) -> None:
        client = FakeGdb([ENTRY_EIP, SIDE_EIP, RETURN_EIP, ENTRY_EIP, RETURN_EIP])
        sides = []
        self.run_pairs(client, [1, 2], lambda *_: None, side_address=SIDE_ADDRESS,
                       side_eip=SIDE_EIP, side_max_hits=1, capture_side=lambda *row: sides.append(row))
        self.assertEqual(len(sides), 1)
        self.assertEqual(client.calls.count(("insert", SIDE_ADDRESS)), 1)
        self.assertEqual(client.armed, {RETURN_ADDRESS})

    def test_side_trace_keeps_middle_and_return_guards(self) -> None:
        client = FakeGdb([ENTRY_EIP, SIDE_EIP, MIDDLE_EIP, SIDE_EIP, RETURN_EIP])
        sides, captures = [], []
        self.run_pairs(client, [1], lambda field, *_: captures.append(field),
                       middle_address=MIDDLE_ADDRESS, middle_eip=MIDDLE_EIP,
                       side_address=SIDE_ADDRESS, side_eip=SIDE_EIP,
                       capture_side=lambda *row: sides.append(row))
        self.assertEqual(len(sides), 2)
        self.assertEqual(captures, ["paired_entry_hit", "paired_middle_hit", "paired_return_hit"])
        self.assertEqual(client.armed, {RETURN_ADDRESS})

    def test_startup_pair_cli_rejects_unsafe_modes_before_connecting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = ["remote_capture.py", "--out-dir", temporary,
                    "--startup-key", "breakpairs:0x1234:0x20:0x23:1"]
            for options in (["--checkpoint-screenshot"], ["--checkpoint-save-state"],
                            ["--state-side-break-start-value", "2"],
                            ["--state-side-break-segmented", "0x1233:0x30"],
                            ["--state-side-break-segmented", "0x4321:0x30", "--state-side-break-poke", "0x20000:00"]):
                with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), patch(
                    "sys.argv", base + options), patch.object(remote_capture, "RspClient") as connection:
                    with self.assertRaises(SystemExit) as error:
                        remote_capture.main()
                    self.assertEqual(error.exception.code, 2)
                    connection.assert_not_called()

    def test_invalid_side_contract_is_rejected_before_arming(self) -> None:
        for options in ({"side_address": SIDE_ADDRESS}, {"side_max_hits": 1},
                        {"side_address": SIDE_ADDRESS, "side_eip": SIDE_EIP},
                        {"side_address": SIDE_ADDRESS, "side_eip": SIDE_EIP,
                         "capture_side": lambda *_: None, "side_max_hits": 0},
                        {"side_address": SIDE_ADDRESS, "side_eip": RETURN_EIP,
                         "capture_side": lambda *_: None}):
            client = FakeGdb([])
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    self.run_pairs(client, [1], lambda *_: None, **options)
                self.assertEqual(client.calls, [])

    def test_startup_pair_action_parser(self) -> None:
        self.assertEqual(remote_capture.parse_segmented_breakpoint_pairs_action(
            "breakpairs:0x1234:0x20:0x23:2+4"), (0x1234, 0x20, 0x23, [2, 4]))
        for action in ("breakpairs:0x1234:0x20:0x20:1", "breakpairs:0x1234:0x20:0x23:2+1",
                       "breakpairs:0x10000:0x20:0x23:1", "breakpairs:0x1234:0x20:1"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                remote_capture.parse_segmented_breakpoint_pairs_action(action)

    def test_startup_pair_movie_records_both_boundaries_and_raw_side_stack(self) -> None:
        tree = ast.parse(Path(remote_capture.__file__).read_text())
        expected_test = ast.dump(ast.parse("key.startswith('breakpairs:')", mode="eval").body)
        block = next(node for node in ast.walk(tree) if isinstance(node, ast.If)
                     and ast.dump(node.test) == expected_test)
        statements = block.body[:-1]  # The final continue belongs to the startup loop.
        client = FakeGdb([ENTRY_EIP, SIDE_EIP, RETURN_EIP])
        client.registers = lambda: {"eip": client.eip, "ds": 0x2345, "ss": 0x2345}
        records, sides = [], []
        environment = dict(vars(remote_capture), key="breakpairs:0x1234:0x20:0x23:1",
            gdb=client, qmp_startup=None, halted_stop="T05", halted_regs=client.registers(),
            args=SimpleNamespace(timeout=7.0, out_dir=Path("unused"), dump_segment="ds",
                dump_size=16, dump_low_memory=True, vga_address=0xA0000,
                omit_checkpoint_vga=True, checkpoint_displaydump=False),
            state_fields=[], state_checkpoints=records, state_side_breakpoint_records=sides,
            state_side_break_segmented=(0x4321, 0x30), state_side_break_max_hits=8,
            vga_size=16, pgm_header=b"", read_segment_state=lambda *_: {"frame_tick": 3},
            breakpoint_stack_snapshot=lambda *_: {"bytes_hex": "01020304"},
            write_state_checkpoint=lambda *args, **_: dict(field=args[2], value=args[3], state=args[6]))
        with contextlib.redirect_stdout(io.StringIO()):
            exec(compile(ast.Module(body=statements, type_ignores=[]), remote_capture.__file__, "exec"), environment)
        self.assertEqual([row["field"] for row in records], ["paired_entry_hit", "paired_return_hit"])
        self.assertEqual(sides[0]["pair_hit"], 1)
        self.assertEqual(sides[0]["stack"], {"bytes_hex": "01020304"})
        self.assertEqual(environment["halted_regs"]["eip"], RETURN_EIP)

    def test_startup_pairs_summary_and_index_use_declared_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            records = []
            for field in ("paired_entry_hit", "paired_return_hit"):
                for hit in (2, 4):
                    checkpoint = capture / "checkpoints" / f"{field}-{hit}"
                    checkpoint.mkdir(parents=True)
                    (checkpoint / "memory.bin").write_bytes(bytes([hit]))
                    records.append(dict(field=field, value=hit))
            (capture / "remote_runtime_registers.json").write_text(json.dumps(dict(
                break_state=dict(startup_paired_breakpoint_series=dict(hits=[2, 4], checkpoints=records)),
                state_checkpoints=records)))
            summary = build_capture_summary(capture)
            series = summary["break_state"]["startup_paired_breakpoint_series"]
            self.assertEqual(series["checkpoint_count"], 4)
            self.assertNotIn("checkpoints", series)
            (capture / "capture_summary.json").write_text(json.dumps(summary))
            for field in ("paired_entry_hit", "paired_return_hit"):
                self.assertEqual(index_checkpoint_series(capture, artifact="memory.bin", field=field)["declared_hits"], [2, 4])

    def test_sparse_triplets_keep_return_guard_and_halt_at_return(self) -> None:
        client = FakeGdb([ENTRY_EIP, ENTRY_EIP, MIDDLE_EIP, RETURN_EIP,
                          ENTRY_EIP, ENTRY_EIP, MIDDLE_EIP, RETURN_EIP])
        captures = []
        stop, registers = self.run_triplets(
            client, [2, 4], lambda field, hit, *_: captures.append((field, hit)))
        self.assertEqual(captures, [
            (field, hit) for hit in (2, 4)
            for field in ("paired_entry_hit", "paired_middle_hit", "paired_return_hit")])
        self.assertEqual((stop, registers["eip"]), ("T05", RETURN_EIP))
        self.assertEqual(client.armed, {RETURN_ADDRESS})
        guarded_continues = [call for call in client.calls
                             if call == ("continue", (MIDDLE_ADDRESS, RETURN_ADDRESS))]
        self.assertEqual(len(guarded_continues), 2)

    def test_adjacent_triplet_uses_step_stops(self) -> None:
        client = FakeGdb([ENTRY_EIP])
        client.step_eips = iter([MIDDLE_EIP, RETURN_EIP])
        client.stop_packet = "S05"
        captures = []
        self.run_triplets(client, [1], lambda *args: captures.append(args))
        self.assertEqual([record[3]["eip"] for record in captures],
                         [ENTRY_EIP, MIDDLE_EIP, RETURN_EIP])
        self.assertEqual(sum(call[0] == "continue" for call in client.calls), 1)
        self.assertEqual(client.armed, {RETURN_ADDRESS})

    def test_return_before_middle_fails_without_crossing_call(self) -> None:
        for immediate in (False, True):
            with self.subTest(immediate=immediate):
                client = FakeGdb([ENTRY_EIP, RETURN_EIP, MIDDLE_EIP])
                if immediate:
                    client.step_eips = iter([RETURN_EIP])
                captures = []
                with self.assertRaisesRegex(RuntimeError, "return before middle"):
                    self.run_triplets(client, [1], lambda field, *_: captures.append(field))
                self.assertEqual(captures, ["paired_entry_hit"])
                self.assertEqual(client.eip, RETURN_EIP)
                self.assertEqual(client.armed, set())

    def test_triplet_wrong_stops_and_capture_failures_clean_all_guards(self) -> None:
        for stops in ([ENTRY_EIP, 0x999], [ENTRY_EIP, MIDDLE_EIP, 0x999]):
            with self.subTest(stops=stops):
                client = FakeGdb(stops)
                with self.assertRaisesRegex(RuntimeError, "wrong instruction"):
                    self.run_triplets(client, [1], lambda *_: None)
                self.assertEqual(client.armed, set())
        for failing_field in ("paired_entry_hit", "paired_middle_hit", "paired_return_hit"):
            with self.subTest(field=failing_field):
                client = FakeGdb([ENTRY_EIP, MIDDLE_EIP, RETURN_EIP])

                def fail_capture(field, *_):
                    if field == failing_field:
                        raise RuntimeError("capture failed")

                with self.assertRaisesRegex(RuntimeError, "capture failed"):
                    self.run_triplets(client, [1], fail_capture)
                self.assertEqual(client.armed, set())

    def test_triplet_timeout_cleans_both_guards(self) -> None:
        client = FakeGdb([ENTRY_EIP])
        original_wait = client.wait_for_stop

        def wait(timeout):
            if client.armed == {MIDDLE_ADDRESS, RETURN_ADDRESS}:
                raise TimeoutError("no middle")
            return original_wait(timeout)

        with patch.object(client, "wait_for_stop", side_effect=wait):
            with self.assertRaisesRegex(TimeoutError, "no middle"):
                self.run_triplets(client, [1], lambda *_: None)
        self.assertEqual(client.armed, set())

    def test_invalid_middle_boundaries_fail_before_arming(self) -> None:
        for boundaries in (
            {"middle_address": MIDDLE_ADDRESS}, {"middle_eip": MIDDLE_EIP},
            {"middle_address": ENTRY_ADDRESS, "middle_eip": MIDDLE_EIP},
            {"middle_address": MIDDLE_ADDRESS, "middle_eip": RETURN_EIP},
        ):
            client = FakeGdb([])
            with self.subTest(boundaries=boundaries):
                with self.assertRaises(ValueError):
                    self.run_pairs(client, [1], lambda *_: None, **boundaries)
                self.assertEqual(client.calls, [])

    def test_middle_field_index_and_summary_preserve_three_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            records = []
            for hit in (2, 4):
                for field in ("paired_entry_hit", "paired_middle_hit", "paired_return_hit"):
                    checkpoint = capture / "checkpoints" / f"{field}-{hit}"
                    checkpoint.mkdir(parents=True)
                    (checkpoint / "memory.bin").write_bytes(bytes([hit]))
                    records.append({"field": field, "value": hit, "state": {"pair_hit": hit}})
            (capture / "remote_runtime_registers.json").write_text(json.dumps({
                "break_state": {"post_resume_paired_breakpoint_series": {
                    "entry": {"linear_address": ENTRY_EIP},
                    "middle": {"segment": 0x1234, "offset": 0x21},
                    "return": {"linear_address": RETURN_EIP},
                    "hits": [2, 4], "checkpoints": records,
                }}, "state_checkpoints": records,
            }), encoding="utf-8")
            summary = build_capture_summary(capture)
            series = summary["break_state"]["post_resume_paired_breakpoint_series"]
            self.assertEqual(series["checkpoint_count"], 6)
            self.assertEqual(series["middle"], {"segment": 0x1234, "offset": 0x21})
            self.assertEqual(summary["counts"]["post_resume_pairs"], 2)
            (capture / "capture_summary.json").write_text(json.dumps(summary), encoding="utf-8")
            result = index_checkpoint_series(capture, artifact="memory.bin", field="paired_middle_hit")
            self.assertEqual(result["declared_hits"], [2, 4])
            self.assertEqual(result["hits"], [2, 4])

    def test_cli_middle_requires_pairs_and_distinct_physical_addresses(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments = ["remote_capture.py", "--out-dir", temporary,
                         "--state-schema", str(ROOT / "tests/fixtures/minimal-project/state.schema.json"),
                         "--resume-checkpoint-script", "checkpointstate:0x12340:frame_tick:23:4",
                         "--resume-next-linear", "0x12343",
                         "--post-resume-break-segmented", "0x1234:0x20",
                         "--post-resume-next-break-linear", "0x12363",
                         "--post-resume-paired-middle-break-segmented", "0x1234:0x21"]
            with patch("sys.argv", arguments + ["--post-resume-paired-break-hit-series", "1,3"]), patch.object(
                remote_capture, "RspClient", side_effect=RuntimeError("validation passed")
            ):
                with self.assertRaisesRegex(RuntimeError, "validation passed"):
                    remote_capture.main()
            for series, middle in (([], "0x1234:0x21"),
                                   (["--post-resume-paired-break-hit-series", "1,3"], "0x1233:0x30"),
                                   (["--post-resume-paired-break-hit-series", "1,3"], "0x1233:0x33")):
                invalid = list(arguments)
                invalid[-1] = middle
                with self.subTest(series=series, middle=middle), contextlib.redirect_stderr(io.StringIO()), patch(
                    "sys.argv", invalid + series
                ), patch.object(remote_capture, "RspClient") as connection:
                    with self.assertRaises(SystemExit) as error:
                        remote_capture.main()
                    self.assertEqual(error.exception.code, 2)
                    connection.assert_not_called()

    def test_launcher_forwards_middle_at_every_stage(self) -> None:
        launcher = (ROOT / "scripts/run-wsl-remotedebug.ps1").read_text(encoding="utf-8")
        self.assertIn('[string]$PostResumePairedMiddleBreakSegmented = ""', launcher)
        self.assertIn('"--post-resume-paired-middle-break-segmented",', launcher)
        self.assertIn('post_resume_paired_middle_break_segmented="$2"', launcher)
        self.assertIn('--post-resume-paired-middle-break-segmented "$post_resume_paired_middle_break_segmented"', launcher)

    def test_sparse_ordinals_capture_both_boundaries_and_halt_at_return(self) -> None:
        client = FakeGdb([ENTRY_EIP, ENTRY_EIP, RETURN_EIP,
                          ENTRY_EIP, ENTRY_EIP, RETURN_EIP])
        captures = []
        stop, registers = self.run_pairs(
            client, [2, 4],
            lambda field, hit, stop, regs: captures.append(
                (field, hit, stop, regs["eip"])),
        )
        self.assertEqual(captures, [
            ("paired_entry_hit", 2, "T05", ENTRY_EIP),
            ("paired_return_hit", 2, "T05", RETURN_EIP),
            ("paired_entry_hit", 4, "T05", ENTRY_EIP),
            ("paired_return_hit", 4, "T05", RETURN_EIP),
        ])
        self.assertEqual((stop, registers["eip"]), ("T05", RETURN_EIP))
        self.assertEqual(client.armed, {RETURN_ADDRESS})
        self.assertEqual([call for call in client.calls if call[0] == "continue"], [
            ("continue", (ENTRY_ADDRESS,)),
            ("continue", (ENTRY_ADDRESS,)),
            ("continue", (RETURN_ADDRESS,)),
            ("continue", (ENTRY_ADDRESS,)),
            ("continue", (ENTRY_ADDRESS,)),
            ("continue", (RETURN_ADDRESS,)),
        ])
        self.assertEqual(client.calls.count(("step",)), 5)

    def test_consecutive_pairs_remain_separate(self) -> None:
        client = FakeGdb([ENTRY_EIP, RETURN_EIP, ENTRY_EIP, RETURN_EIP])
        captures = []
        self.run_pairs(client, [1, 2], lambda field, hit, *_: captures.append((field, hit)))
        self.assertEqual(captures, [("paired_entry_hit", 1), ("paired_return_hit", 1),
                                    ("paired_entry_hit", 2), ("paired_return_hit", 2)])

    def test_single_instruction_pair_keeps_actual_step_stop(self) -> None:
        client = FakeGdb([ENTRY_EIP])
        client.step_eips = iter([RETURN_EIP])
        client.stop_packet = "S05"
        captures = []
        stop, registers = self.run_pairs(client, [1], lambda *args: captures.append(args))
        self.assertEqual(stop, "S05")
        self.assertEqual(registers["eip"], RETURN_EIP)
        self.assertEqual(len(captures), 2)
        self.assertEqual(sum(call[0] == "continue" for call in client.calls), 1)

    def test_exit_or_nontrap_stop_is_not_counted(self) -> None:
        for packet in ("W00", "X0b", "S02"):
            client = FakeGdb([ENTRY_EIP])
            client.stop_packet = packet
            captures = []
            with self.subTest(packet=packet):
                with self.assertRaisesRegex(RuntimeError, "unexpected stop"):
                    self.run_pairs(client, [1], lambda *args: captures.append(args))
                self.assertEqual(captures, [])
                self.assertEqual(client.armed, set())

    def test_wrong_boundary_cleans_up_and_never_captures_wrong_stop(self) -> None:
        for stops, hits, expected_count in (([0x999], [2], 0),
                                             ([ENTRY_EIP, 0x999], [1], 1)):
            with self.subTest(stops=stops):
                client = FakeGdb(stops)
                captures = []
                with self.assertRaisesRegex(RuntimeError, "wrong instruction"):
                    self.run_pairs(client, hits, lambda *args: captures.append(args))
                self.assertEqual(len(captures), expected_count)
                self.assertEqual(client.armed, set())

    def test_capture_failure_cleans_up(self) -> None:
        for failing_field in ("paired_entry_hit", "paired_return_hit"):
            client = FakeGdb([ENTRY_EIP, RETURN_EIP])

            def fail_capture(field, *_):
                if field == failing_field:
                    raise RuntimeError("capture failed")

            with self.subTest(field=failing_field):
                with self.assertRaisesRegex(RuntimeError, "capture failed"):
                    self.run_pairs(client, [1], fail_capture)
                self.assertEqual(client.armed, set())

    def test_timeout_cleans_up_and_retains_original_error(self) -> None:
        client = FakeGdb([])
        with patch.object(client, "wait_for_stop", side_effect=TimeoutError("no boundary")):
            with self.assertRaisesRegex(TimeoutError, "no boundary"):
                self.run_pairs(client, [1], lambda *_: None)
        self.assertEqual(client.armed, set())

    def test_invalid_ordinals_do_not_arm_breakpoints(self) -> None:
        for hits in ([], [0], [1, 1], [2, 1]):
            client = FakeGdb([])
            with self.subTest(hits=hits):
                with self.assertRaises(ValueError):
                    self.run_pairs(client, hits, lambda *_: None)
                self.assertEqual(client.calls, [])

    def test_aliasing_boundaries_are_rejected_before_arming(self) -> None:
        client = FakeGdb([])
        with self.assertRaisesRegex(ValueError, "distinct"):
            remote_capture.stop_on_post_resume_paired_breakpoint_series(
                client, entry_address=ENTRY_ADDRESS, entry_eip=ENTRY_EIP,
                return_address=0x12330030, return_eip=ENTRY_EIP,
                hit_counts=[1], timeout=7.0, capture_boundary=lambda *_: None,
            )
        self.assertEqual(client.calls, [])

    def test_paired_fields_are_independently_indexed_and_summary_is_compact(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary)
            records = []
            for field in ("paired_entry_hit", "paired_return_hit"):
                for hit in (2, 4):
                    checkpoint = capture / "checkpoints" / f"{field}-{hit}"
                    checkpoint.mkdir(parents=True)
                    (checkpoint / "memory.bin").write_bytes(bytes([hit]))
                    records.append({"field": field, "value": hit, "state": {"pair_hit": hit}})
            (capture / "remote_runtime_registers.json").write_text(json.dumps({
                "break_state": {"post_resume_paired_breakpoint_series": {
                    "entry": {"linear_address": ENTRY_EIP},
                    "return": {"linear_address": RETURN_EIP},
                    "hits": [2, 4], "checkpoints": records,
                }}, "state_checkpoints": records,
            }), encoding="utf-8")
            summary = build_capture_summary(capture)
            series = summary["break_state"]["post_resume_paired_breakpoint_series"]
            self.assertNotIn("checkpoints", series)
            self.assertEqual(series["checkpoint_count"], 4)
            self.assertEqual(series["hits"], [2, 4])
            self.assertEqual(summary["counts"]["post_resume_pairs"], 2)
            (capture / "capture_summary.json").write_text(json.dumps(summary), encoding="utf-8")
            for field in ("paired_entry_hit", "paired_return_hit"):
                result = index_checkpoint_series(capture, artifact="memory.bin", field=field)
                self.assertEqual(result["declared_hits"], [2, 4])
                self.assertEqual(result["hits"], [2, 4])

    def test_cli_accepts_pairs_and_rejects_ambiguous_or_mutating_modes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            arguments = ["remote_capture.py", "--out-dir", temporary,
                         "--state-schema", str(ROOT / "tests/fixtures/minimal-project/state.schema.json"),
                         "--resume-checkpoint-script", "checkpointstate:0x12340:frame_tick:23:4",
                         "--resume-next-linear", "0x12343",
                         "--post-resume-break-segmented", "0x1234:0x20",
                         "--post-resume-next-break-linear", "0x12363",
                         "--post-resume-paired-break-hit-series", "1,3,7"]
            with patch("sys.argv", arguments), patch.object(
                remote_capture, "RspClient", side_effect=RuntimeError("validation passed")
            ):
                with self.assertRaisesRegex(RuntimeError, "validation passed"):
                    remote_capture.main()
            invalid_options = [
                ["--post-resume-break-hit-count", "2"],
                ["--post-resume-next-break-hit-count", "2"],
                ["--post-resume-break-hit-series", "1,2"],
                ["--post-resume-next-break-hit-series", "1,2"],
                ["--post-resume-poke", "0x12000:00"],
                ["--checkpoint-screenshot"],
                ["--checkpoint-save-state"],
                ["--post-resume-display-history-capacity", "2"],
                ["--post-resume-next-break-segmented", "0x1234:0x20"],
            ]
            for options in invalid_options:
                with self.subTest(options=options), contextlib.redirect_stderr(io.StringIO()), patch("sys.argv", arguments + options), patch.object(
                    remote_capture, "RspClient"
                ) as connection:
                    with self.assertRaises(SystemExit) as error:
                        remote_capture.main()
                    self.assertEqual(error.exception.code, 2)
                    connection.assert_not_called()
            for flag, value in (("--post-resume-next-break-linear", "0x12360"),
                                ("--resume-checkpoint-script", "")):
                invalid = list(arguments)
                invalid[invalid.index(flag) + 1] = value
                with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()), patch("sys.argv", invalid), patch.object(
                    remote_capture, "RspClient"
                ) as connection:
                    with self.assertRaises(SystemExit) as error:
                        remote_capture.main()
                    self.assertEqual(error.exception.code, 2)
                    connection.assert_not_called()

    def test_launcher_forwards_optional_pair_series(self) -> None:
        launcher = (ROOT / "scripts/run-wsl-remotedebug.ps1").read_text(encoding="utf-8")
        self.assertTrue('[string]$PostResumePairedBreakHitSeries = ""' in launcher)
        self.assertTrue('"--post-resume-paired-break-hit-series",' in launcher)
        self.assertTrue('post_resume_paired_break_hit_series="$2"' in launcher)
        self.assertTrue('--post-resume-paired-break-hit-series "$post_resume_paired_break_hit_series"' in launcher)


if __name__ == "__main__":
    unittest.main()
