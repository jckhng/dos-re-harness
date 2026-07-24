from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).parents[1] / "tools" / "decode_cga_text.py"
SPEC = importlib.util.spec_from_file_location("decode_cga_text", MODULE_PATH)
assert SPEC and SPEC.loader
DECODER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DECODER)


class DecodeCgaTextTests(unittest.TestCase):
    def test_foreground_then_background_nibble_order(self) -> None:
        indexed, unexpected = DECODER.decode_text_attributes(
            bytes([0xDD, 0x1E, 0xDD, 0xA4]),
            columns=2,
            rows=1,
        )
        self.assertEqual(indexed, bytes([0x0E, 0x01, 0x04, 0x0A]))
        self.assertEqual(unexpected, {})

    def test_rejects_wrong_raw_size(self) -> None:
        with self.assertRaisesRegex(ValueError, "expected 4"):
            DECODER.decode_text_attributes(b"\xdd\x1e", columns=2, rows=1)

    def test_rejects_unexpected_character_by_default(self) -> None:
        with self.assertRaisesRegex(ValueError, "0x20:1"):
            DECODER.decode_text_attributes(
                bytes([0x20, 0x1E]),
                columns=1,
                rows=1,
            )


if __name__ == "__main__":
    unittest.main()