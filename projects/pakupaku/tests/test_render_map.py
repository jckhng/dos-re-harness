import sys
import unittest
from pathlib import Path


TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

from render_map import MAP_HEIGHT, MAP_WIDTH, WIDTH, blit_map_tile, decode_map


class RenderMapTests(unittest.TestCase):
    def test_rle_expands_to_28_by_31(self):
        encoded = bytes([0xFF, 3] * 6 + [0xEA, 3])
        decoded = decode_map(encoded)
        self.assertEqual(len(decoded), MAP_WIDTH * MAP_HEIGHT)
        self.assertEqual(set(decoded), {3})

    def test_truncated_run_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "truncated"):
            decode_map(bytes([0x81]))

    def test_tile_blitter_selects_odd_and_even_alignment_planes(self):
        tiles = bytearray(24)
        tiles[0:4] = bytes([0x12, 0xF0, 0x34, 0x0F])
        tiles[12:16] = bytes([0x56, 0xF0, 0x78, 0x0F])

        odd = bytearray([0xAA] * (WIDTH * 3))
        blit_map_tile(odd, bytes(tiles), 0, 1, 0)
        self.assertEqual(odd[1], 0xB2)
        self.assertEqual(odd[3], 0x3E)

        even = bytearray([0xAA] * (WIDTH * 3))
        blit_map_tile(even, bytes(tiles), 0, 2, 0)
        self.assertEqual(even[3], 0xF6)
        self.assertEqual(even[5], 0x7A)


if __name__ == "__main__":
    unittest.main()
