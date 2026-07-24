"""State parsing and field-level differential comparison."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

from .schema import Field, parse_dump


def parse_dump_file(
    dump_path: Path,
    fields: Iterable[Field],
    base_offset: int = 0,
) -> dict[str, Any]:
    data = dump_path.read_bytes()
    return {
        "_meta": {
            "dump": str(dump_path),
            "dump_size": len(data),
            "base_offset": base_offset,
        },
        **parse_dump(data, fields, base_offset),
    }


def load_state(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict):
        raise ValueError(f"{path}: state JSON must be an object")
    return document


def diff_states(
    left: dict[str, Any],
    right: dict[str, Any],
    fields: Iterable[Field],
    strict: bool,
) -> tuple[list[tuple[Field, Any, Any]], int, int]:
    differences: list[tuple[Field, Any, Any]] = []
    matches = 0
    skipped = 0
    for field in fields:
        left_present = field.name in left
        right_present = field.name in right
        if not left_present or not right_present:
            if strict:
                differences.append(
                    (
                        field,
                        left.get(field.name, "<missing>"),
                        right.get(field.name, "<missing>"),
                    )
                )
            else:
                skipped += 1
            continue
        if left[field.name] == right[field.name]:
            matches += 1
        else:
            differences.append((field, left[field.name], right[field.name]))
    return differences, matches, skipped
