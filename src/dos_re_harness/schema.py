"""Schema-driven decoding of memory captured from a DOS process."""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


_FORMATS = {
    "u8": "<B",
    "s8": "<b",
    "u16le": "<H",
    "s16le": "<h",
    "u32le": "<I",
    "s32le": "<i",
}


def parse_int(value: int | str) -> int:
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise TypeError(f"expected integer or integer string, got {type(value).__name__}")


@dataclass(frozen=True)
class Field:
    name: str
    offset: int
    size: int
    format: str
    note: str = ""

    def decode(self, data: bytes, base_offset: int = 0) -> int | None:
        file_offset = self.offset - base_offset
        if file_offset < 0 or file_offset + self.size > len(data):
            return None
        return int(struct.unpack_from(_FORMATS[self.format], data, file_offset)[0])


def _field_from_json(item: dict[str, Any]) -> Field:
    name = item.get("name")
    format_name = item.get("type")
    if not isinstance(name, str) or not name:
        raise ValueError("schema field requires a non-empty name")
    if format_name not in _FORMATS:
        raise ValueError(
            f"schema field {name!r} has unsupported type {format_name!r}; "
            f"expected one of {', '.join(sorted(_FORMATS))}"
        )
    size = struct.calcsize(_FORMATS[format_name])
    return Field(
        name=name,
        offset=parse_int(item.get("offset")),
        size=size,
        format=format_name,
        note=str(item.get("note", "")),
    )


def _expand_blocks(document: dict[str, Any]) -> list[dict[str, Any]]:
    expanded: list[dict[str, Any]] = []
    for block in document.get("blocks", []):
        instances = block.get("instances")
        templates = block.get("fields")
        if not isinstance(instances, list) or not isinstance(templates, list):
            raise ValueError("schema block requires instances and fields arrays")
        for instance in instances:
            label = str(instance["name"])
            base = parse_int(instance["base"])
            for template in templates:
                item = dict(template)
                item["name"] = str(item["name"]).format(instance=label)
                item["offset"] = base + parse_int(item["offset"])
                expanded.append(item)
    return expanded


def load_schema(path: Path) -> list[Field]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    items = document.get("fields") if isinstance(document, dict) else None
    if not isinstance(items, list):
        raise ValueError(f"{path}: schema requires a fields array")
    fields = [_field_from_json(item) for item in [*items, *_expand_blocks(document)]]
    names = [field.name for field in fields]
    if len(names) != len(set(names)):
        raise ValueError(f"{path}: schema field names must be unique")
    return fields


def parse_dump(data: bytes, fields: Iterable[Field], base_offset: int = 0) -> dict[str, int]:
    result: dict[str, int] = {}
    for field in fields:
        value = field.decode(data, base_offset)
        if value is not None:
            result[field.name] = value
    return result
