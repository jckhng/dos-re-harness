"""Dependency-free comparison of raw indexed framebuffers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def compare_raw_frames(
    expected: bytes,
    actual: bytes,
    width: int,
    height: int,
) -> tuple[dict[str, Any], bytes]:
    if width <= 0 or height <= 0:
        raise ValueError("frame width and height must be positive")
    size = width * height
    if len(expected) != size or len(actual) != size:
        raise ValueError(
            f"raw frames must both be {size} bytes for {width}x{height}; "
            f"got {len(expected)} and {len(actual)}"
        )
    changed = [index for index, pair in enumerate(zip(expected, actual)) if pair[0] != pair[1]]
    deltas = bytes(abs(left - right) for left, right in zip(expected, actual))
    if changed:
        xs = [index % width for index in changed]
        ys = [index // width for index in changed]
        bbox = [min(xs), min(ys), max(xs) + 1, max(ys) + 1]
    else:
        bbox = None
    return {
        "width": width,
        "height": height,
        "total_pixels": size,
        "diff_pixels": len(changed),
        "diff_ratio": len(changed) / size,
        "max_index_delta": max(deltas, default=0),
        "bbox": bbox,
    }, deltas


def write_raw_diff(
    expected_path: Path,
    actual_path: Path,
    width: int,
    height: int,
    json_path: Path | None,
    pgm_path: Path | None,
) -> dict[str, Any]:
    result, deltas = compare_raw_frames(
        expected_path.read_bytes(), actual_path.read_bytes(), width, height
    )
    result.update({"expected": str(expected_path), "actual": str(actual_path)})
    if json_path:
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    if pgm_path:
        pgm_path.parent.mkdir(parents=True, exist_ok=True)
        pgm_path.write_bytes(f"P5\n{width} {height}\n255\n".encode("ascii") + deltas)
    return result
