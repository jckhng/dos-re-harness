"""Portable JSONL trace comparison."""

from __future__ import annotations

from contextlib import closing
import gzip
import json
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable, Iterator


@dataclass(frozen=True)
class MissingTraceValue:
    def __repr__(self) -> str:
        return "<missing>"


MISSING_TRACE_VALUE = MissingTraceValue()


def iter_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    stream = (
        gzip.open(path, "rt", encoding="utf-8")
        if path.suffix == ".gz"
        else path.open(encoding="utf-8")
    )
    with stream:
        for number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            value = json.loads(line)
            if not isinstance(value, dict):
                raise ValueError(f"{path}:{number}: trace row must be an object")
            yield value


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    return list(iter_jsonl(path))


def first_trace_difference(
    original: Iterable[dict[str, Any]],
    reimplementation: Iterable[dict[str, Any]],
) -> tuple[int, dict[str, tuple[Any, Any]]] | None:
    return _compare_rows(original, reimplementation)[1]


def compare_jsonl(
    original: Path,
    reimplementation: Path,
) -> tuple[int, tuple[int, dict[str, tuple[Any, Any]]] | None]:
    with closing(iter_jsonl(original)) as left, closing(iter_jsonl(reimplementation)) as right:
        return _compare_rows(left, right)


def _compare_rows(
    original: Iterable[dict[str, Any]],
    reimplementation: Iterable[dict[str, Any]],
) -> tuple[int, tuple[int, dict[str, tuple[Any, Any]]] | None]:
    missing = object()

    def display(value: Any) -> Any:
        return MISSING_TRACE_VALUE if value is missing else value

    count = 0
    for index, (left, right) in enumerate(
        zip_longest(original, reimplementation, fillvalue=None)
    ):
        count = index + 1
        if left is None or right is None:
            return count, (index, {
                "row": (
                    left if left is not None else MISSING_TRACE_VALUE,
                    right if right is not None else MISSING_TRACE_VALUE,
                )
            })
        differences = {}
        for key in sorted(set(left) | set(right)):
            left_value = left.get(key, missing)
            right_value = right.get(key, missing)
            if left_value != right_value:
                differences[key] = (display(left_value), display(right_value))
        if differences:
            return count, (index, differences)
    return count, None
