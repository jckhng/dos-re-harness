#!/usr/bin/env python3
"""Score candidate map origins against a private raw CGA capture."""

from __future__ import annotations

import argparse
from pathlib import Path

from render_map import (
    HEIGHT,
    MAP_HEIGHT,
    MAP_WIDTH,
    TILE_HEIGHT,
    TILE_WIDTH,
    WIDTH,
    blit_map_tile,
    decode_map,
)


def render_attributes(
    cells: bytes, tiles: bytes, origin_x: int, origin_y: int
) -> bytearray:
    attributes = bytearray(WIDTH * HEIGHT)
    for row in range(MAP_HEIGHT):
        for column in range(MAP_WIDTH):
            blit_map_tile(
                attributes,
                tiles,
                cells[row * MAP_WIDTH + column],
                origin_x + column * TILE_WIDTH,
                origin_y + row * TILE_HEIGHT,
            )
    return attributes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    cells = decode_map((args.data_dir / "MAP.DAT").read_bytes())
    tiles = (args.data_dir / "MAPTILES.DAT").read_bytes()
    observed = (args.capture / "remote_runtime_vga.bin").read_bytes()

    scores = []
    for origin_y in range(8):
        for origin_x in range(8):
            rendered = render_attributes(cells, tiles, origin_x, origin_y)
            changed = 0
            for y in range(origin_y, origin_y + MAP_HEIGHT * TILE_HEIGHT):
                for x in range(origin_x | 1, origin_x + MAP_WIDTH * TILE_WIDTH, 2):
                    offset = y * WIDTH + x
                    changed += rendered[offset] != observed[offset]
            scores.append((changed, origin_x, origin_y))
    for changed, origin_x, origin_y in sorted(scores)[:10]:
        print(f"differences={changed} origin=({origin_x},{origin_y})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
