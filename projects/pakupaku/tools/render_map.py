#!/usr/bin/env python3
"""Render MAP.DAT and MAPTILES.DAT into Paku Paku's raw CGA text buffer."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


WIDTH = 160
HEIGHT = 100
MAP_WIDTH = 28
MAP_HEIGHT = 31
TILE_WIDTH = 3
TILE_HEIGHT = 3
TILE_BYTES = 24


def decode_map(data: bytes) -> bytes:
    cells = bytearray()
    cursor = 0
    while cursor < len(data):
        control = data[cursor]
        cursor += 1
        if control & 0x80:
            if cursor == len(data):
                raise ValueError("truncated map run")
            cells.extend([data[cursor]] * (control & 0x7F))
            cursor += 1
        else:
            cells.append(control)
    expected = MAP_WIDTH * MAP_HEIGHT
    if len(cells) != expected:
        raise ValueError(f"map expands to {len(cells)} cells, expected {expected}")
    return bytes(cells)


def blit_map_tile(
    attributes: bytearray, tiles: bytes, tile: int, x: int, y: int
) -> None:
    if tile * TILE_BYTES + TILE_BYTES > len(tiles):
        raise ValueError(f"tile index {tile} exceeds MAPTILES.DAT")
    source = tile * TILE_BYTES + (TILE_BYTES // 2 if x % 2 == 0 else 0)
    destination = y * WIDTH + (x | 1)
    for _ in range(TILE_HEIGHT):
        for column in range(2):
            paint = tiles[source]
            mask = tiles[source + 1]
            target = destination + column * 2
            attributes[target] = paint | (mask & attributes[target])
            source += 2
        destination += WIDTH


def render_map(map_data: bytes, tile_data: bytes) -> bytes:
    cells = decode_map(map_data)
    attributes = bytearray(WIDTH * HEIGHT)
    for row in range(MAP_HEIGHT):
        for column in range(MAP_WIDTH):
            blit_map_tile(
                attributes,
                tile_data,
                cells[row * MAP_WIDTH + column],
                1 + column * TILE_WIDTH,
                row * TILE_HEIGHT,
            )
    raw = bytearray(WIDTH * HEIGHT)
    raw[0::2] = bytes([0xDD]) * (WIDTH * HEIGHT // 2)
    raw[1::2] = attributes[1::2]
    return bytes(raw)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("data_dir", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    rendered = render_map(
        (args.data_dir / "MAP.DAT").read_bytes(),
        (args.data_dir / "MAPTILES.DAT").read_bytes(),
    )
    args.output.write_bytes(rendered)
    print(
        json.dumps(
            {
                "format_version": 1,
                "width": WIDTH,
                "height": HEIGHT,
                "sha256": hashlib.sha256(rendered).hexdigest(),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
