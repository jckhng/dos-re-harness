"""Portable JSONL trace comparison."""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class MissingTraceValue:
    def __repr__(self) -> str:
        return "<missing>"


MISSING_TRACE_VALUE = MissingTraceValue()


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{number}: trace row must be an object")
        rows.append(value)
    return rows


def first_trace_difference(
    original: list[dict[str, Any]],
    reimplementation: list[dict[str, Any]],
) -> tuple[int, dict[str, tuple[Any, Any]]] | None:
    missing = object()

    def display(value: Any) -> Any:
        return MISSING_TRACE_VALUE if value is missing else value

    for index, (left, right) in enumerate(
        zip_longest(original, reimplementation, fillvalue=None)
    ):
        if left is None or right is None:
            return index, {
                "row": (
                    left if left is not None else MISSING_TRACE_VALUE,
                    right if right is not None else MISSING_TRACE_VALUE,
                )
            }
        differences = {}
        for key in sorted(set(left) | set(right)):
            left_value = left.get(key, missing)
            right_value = right.get(key, missing)
            if left_value != right_value:
                differences[key] = (display(left_value), display(right_value))
        if differences:
            return index, differences
    return None
