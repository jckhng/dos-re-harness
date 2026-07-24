#!/usr/bin/env python3
"""Compare two private Paku Paku harness captures without exposing their bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROW_BYTES = 160
SCREEN_ROWS = 100


def runs(values: list[int]) -> list[list[int]]:
    if not values:
        return []
    result: list[list[int]] = []
    start = previous = values[0]
    for value in values[1:]:
        if value != previous + 1:
            result.append([start, previous])
            start = value
        previous = value
    result.append([start, previous])
    return result


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def compare_screen(left: bytes, right: bytes) -> dict[str, object]:
    expected = ROW_BYTES * SCREEN_ROWS
    if len(left) != expected or len(right) != expected:
        raise ValueError(f"screen dumps must each contain {expected} bytes")
    changed = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
    stable_rows = [
        row
        for row in range(SCREEN_ROWS)
        if left[row * ROW_BYTES : (row + 1) * ROW_BYTES]
        == right[row * ROW_BYTES : (row + 1) * ROW_BYTES]
    ]
    stable_regions = []
    for first, last in runs(stable_rows):
        region = left[first * ROW_BYTES : (last + 1) * ROW_BYTES]
        stable_regions.append(
            {
                "x": 0,
                "y": first,
                "width": ROW_BYTES,
                "height": last - first + 1,
                "sha256": sha256(region),
            }
        )
    return {
        "left_sha256": sha256(left),
        "right_sha256": sha256(right),
        "changed_byte_count": len(changed),
        "changed_row_runs": runs(sorted({index // ROW_BYTES for index in changed})),
        "stable_regions": stable_regions,
    }


def compare_memory(left: bytes, right: bytes) -> dict[str, object]:
    if len(left) != len(right):
        raise ValueError("memory dumps must have equal lengths")
    changed = [index for index, pair in enumerate(zip(left, right)) if pair[0] != pair[1]]
    return {
        "left_sha256": sha256(left),
        "right_sha256": sha256(right),
        "changed_byte_count": len(changed),
        "changed_offset_runs": [
            {"first": first, "last": last, "length": last - first + 1}
            for first, last in runs(changed)
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("left", type=Path)
    parser.add_argument("right", type=Path)
    args = parser.parse_args()

    result = {
        "format_version": 1,
        "screen": compare_screen(
            (args.left / "remote_runtime_vga.bin").read_bytes(),
            (args.right / "remote_runtime_vga.bin").read_bytes(),
        ),
        "data_segment": compare_memory(
            (args.left / "remote_runtime_ds.bin").read_bytes(),
            (args.right / "remote_runtime_ds.bin").read_bytes(),
        ),
    }
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
