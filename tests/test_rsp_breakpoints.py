from __future__ import annotations

import sys
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from dos_re_harness.remote_capture import RspClient


class RspBreakpointTests(unittest.TestCase):
    def setUp(self) -> None:
        self.client = RspClient.__new__(RspClient)
        self.packets: list[str] = []
        self.responses: list[str] = []
        self.client.packet = self._packet

    def _packet(self, payload: str) -> str:
        self.packets.append(payload)
        return self.responses.pop(0) if self.responses else "OK"

    def test_duplicate_insert_sends_one_trap(self) -> None:
        self.client.insert_breakpoint(0x12345678)
        self.client.insert_breakpoint(0x12345678)
        self.client.remove_breakpoint(0x12345678)
        self.assertEqual(self.packets, ["Z0,12345678,1", "z0,12345678,1"])

    def test_removed_breakpoint_can_be_inserted_again(self) -> None:
        self.client.insert_breakpoint(0x1234)
        self.client.remove_breakpoint(0x1234)
        self.client.insert_breakpoint(0x1234)
        self.assertEqual(self.packets, ["Z0,1234,1", "z0,1234,1", "Z0,1234,1"])

    def test_failed_insert_can_be_retried(self) -> None:
        self.responses = ["E01", "OK"]
        with self.assertRaisesRegex(RuntimeError, "insertion failed"):
            self.client.insert_breakpoint(0x1234)
        self.client.insert_breakpoint(0x1234)
        self.client.insert_breakpoint(0x1234)
        self.assertEqual(self.packets, ["Z0,1234,1", "Z0,1234,1"])

    def test_failed_remove_keeps_registration(self) -> None:
        self.client.insert_breakpoint(0x1234)
        self.responses = ["E01"]
        with self.assertRaisesRegex(RuntimeError, "removal failed"):
            self.client.remove_breakpoint(0x1234)
        self.client.insert_breakpoint(0x1234)
        self.assertEqual(self.packets, ["Z0,1234,1", "z0,1234,1"])

    def test_unknown_remove_still_reaches_backend(self) -> None:
        self.client.remove_breakpoint(0x1234)
        self.assertEqual(self.packets, ["z0,1234,1"])

    def test_distinct_kinds_are_not_conflated(self) -> None:
        self.client.insert_breakpoint(0x1234, kind=1)
        self.client.insert_breakpoint(0x1234, kind=2)
        self.client.insert_breakpoint(0x1234, kind=2)
        self.assertEqual(self.packets, ["Z0,1234,1", "Z0,1234,2"])


if __name__ == "__main__":
    unittest.main()
