#!/usr/bin/env python3
"""Decode Paku Paku's CGA text attributes into 160x100 indexed pixels."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path

CGA_PALETTE = (
    (0x00, 0x00, 0x00),
    (0x00, 0x00, 0xAA),
    (0x00, 0xAA, 0x00),
    (0x00, 0xAA, 0xAA),
    (0xAA, 0x00, 0x00),
    (0xAA, 0x00, 0xAA),
    (0xAA, 0x55, 0x00),
    (0xAA, 0xAA, 0xAA),
    (0x55, 0x55, 0x55),
    (0x55, 0x55, 0xFF),
    (0x55, 0xFF, 0x55),
    (0x55, 0xFF, 0xFF),
    (0xFF, 0x55, 0x55),
    (0xFF, 0x55, 0xFF),
    (0xFF, 0xFF, 0x55),
    (0xFF, 0xFF, 0xFF),
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode_text_attributes(
    raw: bytes,
    *,
    columns: int = 80,
    rows: int = 100,
    expected_character: int = 0xDD,
    strict_characters: bool = True,
) -> tuple[bytes, Counter[int]]:
    expected_size = columns * rows * 2
    if len(raw) != expected_size:
        raise ValueError(
            f"expected {expected_size} text-memory bytes, got {len(raw)}"
        )

    pixels = bytearray(columns * 2 * rows)
    unexpected: Counter[int] = Counter()
    for cell in range(columns * rows):
        character = raw[cell * 2]
        attribute = raw[cell * 2 + 1]
        if character != expected_character:
            unexpected[character] += 1
        pixels[cell * 2] = attribute & 0x0F
        pixels[cell * 2 + 1] = (attribute >> 4) & 0x0F

    if strict_characters and unexpected:
        detail = ", ".join(
            f"0x{value:02x}:{count}" for value, count in sorted(unexpected.items())
        )
        raise ValueError(f"unexpected text characters: {detail}")
    return bytes(pixels), unexpected


def ppm_bytes(indexed: bytes, width: int, height: int) -> bytes:
    rgb = bytearray(len(indexed) * 3)
    for offset, index in enumerate(indexed):
        rgb[offset * 3:offset * 3 + 3] = bytes(CGA_PALETTE[index])
    return f"P6\n{width} {height}\n255\n".encode("ascii") + rgb


def write_outputs(input_path: Path, output_prefix: Path, allow_characters: bool) -> dict:
    raw = input_path.read_bytes()
    indexed, unexpected = decode_text_attributes(
        raw,
        strict_characters=not allow_characters,
    )
    width = 160
    height = 100
    indexed_path = output_prefix.with_suffix(".indexed.bin")
    pgm_path = output_prefix.with_suffix(".pgm")
    ppm_path = output_prefix.with_suffix(".ppm")
    metadata_path = output_prefix.with_suffix(".json")

    indexed_path.write_bytes(indexed)
    pgm_path.write_bytes(f"P5\n{width} {height}\n15\n".encode("ascii") + indexed)
    ppm_path.write_bytes(ppm_bytes(indexed, width, height))
    metadata = {
        "format_version": 1,
        "input": str(input_path),
        "input_sha256": sha256(raw),
        "encoding": "cga-text-0xdd-foreground-background-pairs",
        "width": width,
        "height": height,
        "indexed_sha256": sha256(indexed),
        "unexpected_characters": {
            f"0x{value:02x}": count for value, count in sorted(unexpected.items())
        },
        "outputs": {
            "indexed": str(indexed_path),
            "pgm": str(pgm_path),
            "ppm": str(ppm_path),
        },
    }
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    return metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output_prefix", type=Path)
    parser.add_argument(
        "--allow-unexpected-characters",
        action="store_true",
        help="decode while reporting character bytes other than 0xdd",
    )
    args = parser.parse_args()
    metadata = write_outputs(
        args.input,
        args.output_prefix,
        args.allow_unexpected_characters,
    )
    print(json.dumps(metadata, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())