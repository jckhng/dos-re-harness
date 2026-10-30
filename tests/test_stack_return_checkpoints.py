from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dos_re_harness import remote_capture


class FakeGdb:
    def __init__(self, words, sp=0x100):
        self.state = {"cs": 0x1234, "ss": 0x2000, "esp": sp, "eip": 0x12380}
        self.memory = {0x20000 + ((sp + index) & 0xFFFF): value
            for index, value in enumerate(struct.pack("<" + "H" * len(words), *words))}
        self.reads = []

    def registers(self):
        return dict(self.state)

    def read_memory(self, address, size):
        self.reads.append((address, size))
        return bytes(self.memory[address + index] for index in range(size))


class StackReturnCheckpointTests(unittest.TestCase):
    def resolve(self, action, gdb, registers):
        return getattr(remote_capture, "_resolve_stack_return_checkpoint")(action, gdb, registers)

    def test_near_return_uses_live_cs(self):
        gdb = FakeGdb([0x4567])
        parsed, evidence = self.resolve("checkpointreturn:near:tick:7:1", gdb, gdb.registers())
        self.assertEqual(parsed, (0x12344567, "tick", [7], 1))
        self.assertEqual(evidence["stack_words"], [0x4567])

    def test_far_return_uses_captured_cs(self):
        gdb = FakeGdb([0x4567, 0x3333])
        parsed, evidence = self.resolve("checkpointreturn:far:tick:7:1", gdb, gdb.registers())
        self.assertEqual(parsed[0], 0x33334567)
        self.assertEqual(evidence["stack_words"], [0x4567, 0x3333])

    def test_iret_preserves_flags_provenance(self):
        gdb = FakeGdb([0x4567, 0x3333, 0x202])
        parsed, evidence = self.resolve("checkpointreturn:iret:tick:7:1", gdb, gdb.registers())
        self.assertEqual(parsed[0], 0x33334567)
        self.assertEqual(evidence["stack_words"], [0x4567, 0x3333, 0x202])
        self.assertEqual(evidence["registers"], gdb.registers())

    def test_stack_bytes_wrap_at_16_bits(self):
        gdb = FakeGdb([0x4567, 0x3333, 0x202], sp=0x1234FFFF)
        parsed, evidence = self.resolve("checkpointreturn:iret:tick:7:1", gdb, gdb.registers())
        self.assertEqual(parsed[0], 0x33334567)
        self.assertEqual([address for address, _ in gdb.reads], [0x2FFFF, 0x20000, 0x20001, 0x20002, 0x20003, 0x20004])

    def test_stopped_boundary_is_required(self):
        gdb = FakeGdb([0x4567])
        with self.assertRaisesRegex(ValueError, "halted"):
            self.resolve("checkpointreturn:near:tick:7:1", gdb, None)
        stale = dict(gdb.state, esp=0x200)
        with self.assertRaisesRegex(ValueError, "changed"):
            self.resolve("checkpointreturn:near:tick:7:1", gdb, stale)
        self.assertEqual(gdb.reads, [])

    def test_malformed_actions_are_rejected_before_read(self):
        gdb = FakeGdb([0x4567])
        for action in ("checkpointreturn:wide:tick:7:1", "checkpointreturn:near:tick:7:0",
                "checkpointreturn:near:tick:7+7:1", "checkpointreturn:near:tick"):
            with self.subTest(action=action), self.assertRaises(ValueError):
                self.resolve(action, gdb, gdb.registers())
        self.assertEqual(gdb.reads, [])

    def test_invalid_segment_is_rejected_before_read(self):
        gdb = FakeGdb([0x4567])
        gdb.state["ss"] = 0x10000
        with self.assertRaisesRegex(ValueError, "16-bit real-mode"):
            self.resolve("checkpointreturn:near:tick:7:1", gdb, gdb.registers())
        self.assertEqual(gdb.reads, [])

    def test_short_stack_read_is_rejected(self):
        gdb = FakeGdb([0x4567])
        gdb.read_memory = lambda address, size: b""
        with self.assertRaisesRegex(ValueError, "short stack read"):
            self.resolve("checkpointreturn:near:tick:7:1", gdb, gdb.registers())

    def test_return_action_can_be_final_saved_checkpoint(self):
        self.assertEqual(remote_capture.checkpoint_save_state_target(
            True, ["checkpointreturn:iret:tick:7:1"], None, False), "startup")


if __name__ == "__main__":
    unittest.main()
