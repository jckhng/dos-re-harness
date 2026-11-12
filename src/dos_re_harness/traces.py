"""Portable JSONL trace comparison."""

from __future__ import annotations

from contextlib import closing
from collections import deque
import gzip
import json
from dataclasses import dataclass
from itertools import zip_longest
from pathlib import Path
from typing import Any, Iterable, Iterator

from .evidence import file_record


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


def write_trace_context(original: Path, reimplementation: Path, out_dir: Path,
                        *, before: int = 8, after: int = 4) -> dict:
    """Retain a bounded window around the first strict row difference."""
    if any(type(value) is not int or not 0 <= value <= 1024 for value in (before, after)):
        raise ValueError("context counts must be integers in 0..1024")
    if out_dir.exists():
        raise ValueError("output must be fresh")
    inputs = [file_record(path) for path in (original, reimplementation)]
    history = deque(maxlen=before)
    window, difference, examined, complete = [], None, 0, False
    with closing(iter_jsonl(original)) as left, closing(iter_jsonl(reimplementation)) as right:
        pairs = zip_longest(left, right)
        for index, (expected, actual) in enumerate(pairs):
            examined = index + 1
            row = dict(index=index, original=expected, reimplementation=actual)
            delta = first_trace_difference(
                [] if expected is None else [expected], [] if actual is None else [actual])
            if difference is None and delta is not None:
                fields = {}
                for field, values in delta[1].items():
                    fields[field] = {
                        side: dict(present=False) if value is MISSING_TRACE_VALUE else dict(present=True, value=value)
                        for side, value in zip(('original', 'reimplementation'), values)
                    }
                difference = dict(index=index, fields=fields)
                window.extend(history)
            if difference is None:
                history.append(row)
                continue
            window.append(row)
            if index >= difference['index'] + after:
                break
        else:
            complete = True
    if inputs != [file_record(path) for path in (original, reimplementation)]:
        raise ValueError("trace inputs changed during comparison")
    report = dict(format_version=1, exact=difference is None, complete=complete,
                  rows_examined=examined, first_difference=difference, inputs=inputs,
                  window=dict(first=window[0]['index'], last=window[-1]['index'], rows=len(window)) if window else None,
                  scope="Strict ordered JSONL prefix comparison with bounded diagnostic context.")
    out_dir.mkdir(parents=True)
    for side in ('original', 'reimplementation'):
        with (out_dir / (side + '-context.jsonl')).open('x', encoding='utf-8') as stream:
            for row in window:
                value = row[side]
                stream.write(json.dumps(dict(index=row['index'], present=value is not None, row=value)) + '\n')
    (out_dir / 'comparison.json').write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return report
