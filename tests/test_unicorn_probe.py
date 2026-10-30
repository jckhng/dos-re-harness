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

    def test_snapshot_preserves_the_existing_saved_register_stack(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex("1f 58 90")
        memory[0x9000:0x9004] = bytes.fromhex("21 43 cd ab")
        result = run_callback(
            bytes(memory), {"ds": 0x100, "ss": 0x100, "esp": 0x8000},
            entry=(0x100, 0x20), return_address=(0x100, 0x22),
            return_kind="snapshot", max_instructions=8,
        )
        self.assertEqual(result.memory, memory)
        self.assertEqual(result.registers["ds"], 0x4321)
        self.assertEqual(result.registers["ax"], 0xABCD)
        self.assertEqual(result.registers["sp"], 0x8004)

    def test_snapshot_executes_iret_without_inventing_an_irq_frame(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020] = 0xCF
        memory[0x9000:0x9006] = bytes.fromhex("30 00 00 02 02 02")
        result = run_callback(
            bytes(memory), {"ss": 0x100, "esp": 0x8000},
            entry=(0x100, 0x20), return_address=(0x200, 0x30),
            return_kind="snapshot", max_instructions=8,
        )
        self.assertEqual(result.memory, memory)
        self.assertEqual(result.registers["sp"], 0x8006)
        self.assertEqual(result.registers["cs"], 0x200)
        self.assertEqual(result.registers["ip"], 0x30)
        self.assertEqual(result.registers["flags"], 0x202)

    def test_instruction_limit_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("eb fe")
        for kind in ("near", "far", "snapshot"):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "instruction limit"):
                run_callback(
                    bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                    entry=(0x100, 0x20), return_address=(0x100, 0x28),
                    return_kind=kind, max_instructions=8,
                )

    def test_observations_preserve_repeated_segmented_positions(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1027] = bytes.fromhex("b9 03 00 43 e2 fd 90")
        result = run_callback(
            bytes(memory), {"ss": 0x100, "esp": 0x8000},
            entry=(0x100, 0x20), return_address=(0x100, 0x26),
            return_kind="snapshot", max_instructions=16,
            observe_addresses=((0x100, 0x23), (0x101, 0x13), (0x100, 0x26)),
        )
        self.assertEqual(result.memory, memory)
        self.assertEqual([row.instruction for row in result.observations], [2, 4, 6])
        self.assertEqual([row.registers["bx"] for row in result.observations], [0, 1, 2])
        self.assertEqual([row.registers["cx"] for row in result.observations], [3, 2, 1])
        self.assertTrue(all((row.registers["cs"], row.registers["ip"]) == (0x100, 0x23)
            for row in result.observations))

    def test_observations_do_not_bypass_device_rejection(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("ee cb")
        with self.assertRaisesRegex(ValueError, "port I/O"):
            run_callback(
                bytes(memory), {"ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x28),
                return_kind="snapshot", max_instructions=8, observe_addresses=((0x100, 0x20),),
            )

    def test_snapshot_stops_at_requested_repeated_boundary(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1027] = bytes.fromhex("b9 03 00 43 e2 fd 90")
        result = run_callback(bytes(memory), {"ss": 0x100, "esp": 0x8000},
            entry=(0x100, 0x20), return_address=(0x100, 0x23), return_kind="snapshot",
            max_instructions=16, stop_hit_count=3, observe_addresses=((0x100, 0x23),))
        self.assertEqual(result.memory, memory)
        self.assertEqual((result.instructions, result.registers["bx"], result.registers["cx"]), (5, 2, 1))
        self.assertEqual([row.instruction for row in result.observations], [2, 4])
        self.assertEqual(result.registers["sp"], 0x8000)

    def test_repeated_snapshot_boundary_still_rejects_devices(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex("90 ee 90")
        with self.assertRaisesRegex(ValueError, "port I/O"):
            run_callback(bytes(memory), {"ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x20), return_kind="snapshot",
                max_instructions=8, stop_hit_count=2)

    def test_repeated_snapshot_boundary_fails_closed_at_cap(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("eb fe")
        with self.assertRaisesRegex(ValueError, "instruction limit"):
            run_callback(bytes(memory), {"ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x20), return_kind="snapshot",
                max_instructions=8, stop_hit_count=9)

    def test_repeated_boundary_requires_positive_count_and_snapshot(self) -> None:
        memory = bytes(0x20000)
        for kind, count in (("snapshot", 0), ("snapshot", -1), ("near", 2), ("far", 2)):
            with self.subTest(kind=kind, count=count), self.assertRaisesRegex(ValueError, "stop hit count"):
                run_callback(memory, {"ss": 0x100, "esp": 0x8000}, entry=(0x100, 0x20),
                    return_address=(0x100, 0x28), return_kind=kind, max_instructions=8, stop_hit_count=count)

    def test_unmapped_access_reports_address_and_instruction_without_mapping_it(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex("a2 00 01")
        with self.assertRaisesRegex(ValueError, "unmapped write at 0x30100 size=1 from 0100:0020"):
            run_callback(bytes(memory), {"ds": 0x3000, "ss": 0x100, "esp": 0x8000},
                entry=(0x100, 0x20), return_address=(0x100, 0x23), return_kind="snapshot", max_instructions=8)

    def test_dos_interrupt_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1023] = bytes.fromhex("cd 21 cb")
        for kind in ("near", "far", "snapshot"):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "interrupt"):
                run_callback(
                    bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                    entry=(0x100, 0x20), return_address=(0x100, 0x28),
                    return_kind=kind, max_instructions=8,
                )

    def test_port_io_fails_closed(self) -> None:
        memory = bytearray(0x20000)
        memory[0x1020:0x1022] = bytes.fromhex("ee cb")
        for kind in ("near", "far", "snapshot"):
            with self.subTest(kind=kind), self.assertRaisesRegex(ValueError, "port I/O"):
                run_callback(
                    bytes(memory), {"cs": 0x100, "ss": 0x100, "esp": 0x8000},
                    entry=(0x100, 0x20), return_address=(0x100, 0x28),
                    return_kind=kind, max_instructions=8,
                )


if __name__ == "__main__":
    unittest.main()
