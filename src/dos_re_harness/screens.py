"""Manifest-defined classification of indexed VGA framebuffers."""

from __future__ import annotations

import hashlib
import json
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import parse_int


@dataclass(frozen=True)
class Region:
    x: int
    y: int
    width: int
    height: int

    def extract(self, raw: bytes, frame_width: int, frame_height: int) -> bytes:
        if (
            self.x < 0
            or self.y < 0
            or self.width <= 0
            or self.height <= 0
            or self.x + self.width > frame_width
            or self.y + self.height > frame_height
        ):
            raise ValueError(f"screen signature region is outside {frame_width}x{frame_height}")
        return b"".join(
            raw[row * frame_width + self.x:row * frame_width + self.x + self.width]
            for row in range(self.y, self.y + self.height)
        )


@dataclass(frozen=True)
class ScreenCondition:
    region: Region
    crc32: int | None
    sha256: str | None
    unique_min: int | None
    unique_max: int | None
    sum_min: int | None
    sum_max: int | None

    def matches(self, raw: bytes, frame_width: int, frame_height: int) -> bool:
        sample = self.region.extract(raw, frame_width, frame_height)
        if self.crc32 is not None and zlib.crc32(sample) != self.crc32:
            return False
        if self.sha256 is not None and hashlib.sha256(sample).hexdigest() != self.sha256:
            return False
        unique = len(set(sample))
        total = sum(sample)
        return (
            (self.unique_min is None or unique >= self.unique_min)
            and (self.unique_max is None or unique <= self.unique_max)
            and (self.sum_min is None or total >= self.sum_min)
            and (self.sum_max is None or total <= self.sum_max)
        )


@dataclass(frozen=True)
class ScreenSignature:
    name: str
    conditions: list[ScreenCondition]

    def matches(self, raw: bytes, frame_width: int, frame_height: int) -> bool:
        return all(
            condition.matches(raw, frame_width, frame_height)
            for condition in self.conditions
        )


class ScreenClassifier:
    def __init__(
        self,
        width: int,
        height: int,
        signatures: list[ScreenSignature],
        unknown_name: str = "unknown",
    ) -> None:
        self.width = width
        self.height = height
        self.signatures = signatures
        self.unknown_name = unknown_name

    @classmethod
    def load(cls, path: Path) -> "ScreenClassifier":
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        width = parse_int(document.get("width", 320))
        height = parse_int(document.get("height", 200))
        signatures: list[ScreenSignature] = []
        for item in document.get("states", []):
            condition_items = item.get("conditions", [item])
            if not isinstance(condition_items, list) or not condition_items:
                raise ValueError(f"{path}: state conditions must be a non-empty array")
            conditions = [
                _condition_from_json(condition, width, height, path)
                for condition in condition_items
            ]
            signatures.append(
                ScreenSignature(
                    name=str(item["name"]),
                    conditions=conditions,
                )
            )
        if not signatures:
            raise ValueError(f"{path}: screen signature file requires at least one state")
        return cls(width, height, signatures, str(document.get("unknown", "unknown")))

    def classify(self, raw: bytes) -> str:
        if len(raw) < self.width * self.height:
            return self.unknown_name
        for signature in self.signatures:
            if signature.matches(raw, self.width, self.height):
                return signature.name
        return self.unknown_name


def _optional_int(item: dict[str, Any], key: str) -> int | None:
    value = item.get(key)
    return parse_int(value) if value is not None else None


def _condition_from_json(
    item: dict[str, Any],
    width: int,
    height: int,
    path: Path,
) -> ScreenCondition:
    region_values = item.get("region", [0, 0, width, height])
    if not isinstance(region_values, list) or len(region_values) != 4:
        raise ValueError(f"{path}: state region must be [x, y, width, height]")
    region = Region(*(parse_int(value) for value in region_values))
    crc_value = item.get("crc32")
    sha_value = item.get("sha256")
    return ScreenCondition(
        region=region,
        crc32=parse_int(crc_value) if crc_value is not None else None,
        sha256=str(sha_value).lower() if sha_value is not None else None,
        unique_min=_optional_int(item, "unique_min"),
        unique_max=_optional_int(item, "unique_max"),
        sum_min=_optional_int(item, "sum_min"),
        sum_max=_optional_int(item, "sum_max"),
    )
