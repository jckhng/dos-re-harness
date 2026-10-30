from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dos_re_harness.remote_capture import RspClient


REGISTERS = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
    "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs")
ENTRY_SEGMENT, ENTRY_OFFSET = 0x1234, 0x56


class RspRegisterWriteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RspClient.__new__(RspClient)
        self.state = dict.fromkeys(REGISTERS, 0)
        self.state.update(cs=ENTRY_SEGMENT, eip=ENTRY_SEGMENT * 16 + ENTRY_OFFSET,
            ss=0x4321, esp=0x100, eflags=0x202)
        self.written: dict[str, int] = {}
        self.memory_writes: list[tuple[int, bytes]] = []
        self.client.registers = lambda: dict(self.state)
        self.client.packet = self._packet
        self.client.write_memory = lambda address, data: self.memory_writes.append((address, data))

    def _packet(self, payload: str) -> str:
        self.assertTrue(payload.startswith("G"))
        values = struct.unpack("<16I", bytes.fromhex(payload[1:]))
        self.written = dict(zip(REGISTERS, values))
        self.state = dict(self.written)
        self.state["eip"] += self.state["cs"] * 16
        return "OK"

    def test_partial_write_preserves_unmentioned_ip_and_registers(self) -> None:
        original = dict(self.state)
        self.client.write_registers({"ecx": 0x789A})
        self.assertEqual(self.written["eip"], ENTRY_OFFSET)
        self.assertEqual(self.state, dict(original, ecx=0x789A))

    def test_segment_only_write_preserves_original_ip(self) -> None:
        self.client.write_registers({"cs": 0x4567})
        self.assertEqual(self.written["eip"], ENTRY_OFFSET)
        self.assertEqual(self.state["eip"], 0x45670 + ENTRY_OFFSET)

    def test_explicit_linear_ip_uses_new_segment(self) -> None:
        self.client.write_registers({"cs": 0x4567, "eip": 0x45670 + 0x89})
        self.assertEqual(self.written["eip"], 0x89)
        self.assertEqual(self.state["eip"], 0x45670 + 0x89)

    def test_explicit_offset_ip_remains_compatible(self) -> None:
        self.client.write_registers({"eip": 0x89})
        self.assertEqual(self.written["eip"], 0x89)

    def test_partial_restore_keeps_synthetic_near_return(self) -> None:
        self.client.write_registers({"ecx": 0x789A})
        self.client.call_near(0x89, self.client.registers())
        self.assertEqual(self.memory_writes, [(0x43210 + 0xFE, struct.pack("<H", ENTRY_OFFSET))])
        self.assertEqual(self.state["ecx"], 0x789A)
        self.assertEqual(self.state["eip"], ENTRY_SEGMENT * 16 + 0x89)


if __name__ == "__main__":
    unittest.main()
