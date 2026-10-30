from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


class PostResumeCheckpointSaveStateTests(unittest.TestCase):
    def callback(self, enabled: bool, immediate: bool = True):
        path = Path(__file__).resolve().parents[1] / "src/dos_re_harness/remote_capture.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        node = next(node for node in ast.walk(tree) if isinstance(node, ast.FunctionDef)
                    and node.name == "capture_state_input_breakpoint")
        calls = []
        records = []
        record = {"path": "checkpoint"}
        args = SimpleNamespace(dump_segment="ds", out_dir=Path("out"), dump_size=16,
                               dump_low_memory=True, vga_address=0, omit_checkpoint_vga=False,
                               checkpoint_dac=False, checkpoint_displaydump=False,
                               checkpoint_screenshot=False, checkpoint_save_state=enabled,
                               timeout=1, post_resume_break_linear=0x1234)

        def finalize(*values):
            calls.append(values)
            self.assertEqual(values[2], 0x1234)
            self.assertIs(values[3], record)
            self.assertEqual(values[5]({}), {"state": 1})
            return "S05", {"ds": 4}

        scope = dict(args=args, qmp_post_resume=SimpleNamespace(supports_immediate_savestate=immediate),
                     gdb=object(), state_fields=[], vga_size=16, pgm_header=b"",
                     state_checkpoints=records, post_resume_break_segmented=None,
                     read_segment_state=lambda *a: {"state": 1},
                     write_state_checkpoint=lambda *a, **k: record,
                     finalize_halted_checkpoint_save_state=finalize)
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(path), "exec"), scope)
        return scope[node.name], calls, records

    def test_requested_save_is_finalized_at_each_halted_hit(self):
        callback, calls, records = self.callback(True)
        callback(6, "S05", {"ds": 4})
        callback(7, "S05", {"ds": 4})
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(records), 2)

    def test_default_does_not_save(self):
        callback, calls, records = self.callback(False, False)
        callback(6, "S05", {"ds": 4})
        self.assertEqual(calls, [])
        self.assertEqual(len(records), 1)

    def test_requested_save_rejects_backend_that_would_step(self):
        callback, calls, _ = self.callback(True, False)
        with self.assertRaisesRegex(RuntimeError, "immediate"):
            callback(6, "S05", {"ds": 4})
        self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main()
