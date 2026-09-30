from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dos_re_harness.unicorn_probe import run_callback


class UnicornProbeTests(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import unicorn  # noqa: F401
        except ImportError:
            self.skipTest("optional Unicorn dependency is not installed")

    def test_far_return_uses_nonzero_segments(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1026] = bytes.fromhex("a1 00 01 40 a3 00")
        memory[0x1026:0x1029] = bytes.fromhex("01 cb 90")
        memory[0x1100:0x1102] = bytes.fromhex("34 12")
        result = run_callback(
            bytes(memory),
            {"cs": 0x100, "ds": 0x100, "ss": 0x100, "esp": 0x8000},
            entry=(0x100, 0x20),
            return_address=(0x100, 0x28),
            return_kind="far",
            max_instructions=16,
        )
        self.assertEqual(result.memory[0x1100:0x1102], bytes.fromhex("35 12"))
        self.assertEqual(result.registers["cs"], 0x100)
        self.assertEqual(result.registers["ip"], 0x28)

    def test_instruction_limit_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("eb fe")
        with self.assertRaisesRegex(ValueError, "instruction limit"):
            run_callback(
                bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x28),
                return_kind="far", max_instructions=8,
            )

    def test_dos_interrupt_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex("cd 21 cb")
        with self.assertRaisesRegex(ValueError, "interrupt"):
            run_callback(
                bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x28),
                return_kind="far", max_instructions=8,
            )

    def test_port_io_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("ee cb")
        with self.assertRaisesRegex(ValueError, "port I/O"):
            run_callback(
                bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x28),
                return_kind="far", max_instructions=8,
            )


if __name__ == "__main__":
    unittest.main()
