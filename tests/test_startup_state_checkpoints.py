from __future__ import annotations

import ast
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dos_re_harness import remote_capture


class StartupStateCheckpointTests(unittest.TestCase):
    def test_startup_checkpoint_actions_preserve_prior_halt(self) -> None:
        callbacks = {"capture_checkpoint", "capture_hold_checkpoint", "capture_script_checkpoint"}
        tree = ast.parse(Path(remote_capture.__file__).read_text(encoding="utf-8"))
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name) and node.func.id == "stop_on_state_checkpoints"
            and len(node.args) > 7 and isinstance(node.args[7], ast.Name) and node.args[7].id in callbacks]
        self.assertEqual({node.args[7].id for node in calls}, callbacks)

        for node in calls:
            for prior_halt in (True, False):
                with self.subTest(action=node.args[7].id, prior_halt=prior_halt):
                    captured = []

                    class FakeGdb:
                        def __init__(self) -> None:
                            self.halted = prior_halt
                            self.halt_calls = 0

                        def halt(self, timeout: float) -> str:
                            if self.halted:
                                raise AssertionError("redundant halt on stopped guest")
                            self.halt_calls += 1
                            self.halted = True
                            return "S05"

                        def insert_breakpoint(self, address: int) -> None:
                            pass

                        def continue_nowait(self) -> None:
                            self.halted = False

                        def wait_for_stop(self, timeout: float) -> str:
                            self.halted = True
                            return "S05"

                        def registers(self) -> dict[str, int]:
                            return {"ds": 0x1234}

                    gdb = FakeGdb()
                    environment = dict(stop_on_state_checkpoints=remote_capture.stop_on_state_checkpoints,
                        gdb=gdb, linear_address=0x12340, field_name="frame_tick", values=[1], observed_values=[1],
                        max_hits=8, args=SimpleNamespace(timeout=1.0), halted_stop="S05" if prior_halt else None,
                        state_side_break_segmented=None, capture_script_side_breakpoint=None,
                        state_side_break_max_hits=None, state_side_break_start_value=None,
                        transition_script_keys=lambda value: None, transition_hold_key=lambda value: None)
                    for name in ("read_checkpoint_state", "read_hold_checkpoint_state", "read_script_checkpoint_state"):
                        environment[name] = lambda registers: {"frame_tick": 1}
                    for name in callbacks:
                        environment[name] = lambda *record: captured.append(record)
                    # Execute the actual startup call site, including its halted-state argument.
                    result = eval(compile(ast.Expression(node), remote_capture.__file__, "eval"), environment)
                    self.assertEqual(result, ("S05", {"ds": 0x1234}, {"frame_tick": 1}, 1))
                    self.assertEqual(gdb.halt_calls, 0 if prior_halt else 1)
                    self.assertEqual(len(captured), 1)


if __name__ == "__main__":
    unittest.main()
