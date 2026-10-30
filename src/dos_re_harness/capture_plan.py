"""Versioned capture requests compiled into the existing adapter interface."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


_FORMAT_VERSION = 1
_FIELDS = {"format_version", "project", "scenario", "movie", "input_script", "adapter_arguments"}


@dataclass(frozen=True)
class CapturePlan:
    path: Path
    sha256: str
    project: Path
    scenario: str
    movie: Path | None
    input_script: Path | None
    adapter_arguments: tuple[tuple[str, str], ...]

    def record(self) -> dict[str, Any]:
        return {
            "format_version": _FORMAT_VERSION,
            "project": str(self.project),
            "scenario": self.scenario,
            "movie": str(self.movie) if self.movie is not None else None,
            "input_script": str(self.input_script) if self.input_script is not None else None,
            "adapter_arguments": dict(self.adapter_arguments),
        }


def load_capture_plan(path: Path) -> CapturePlan:
    path = path.resolve()
    raw = path.read_bytes()
    document = json.loads(raw.decode("utf-8-sig"))
    if not isinstance(document, dict):
        raise ValueError("capture plan must be an object")
    if type(document.get("format_version")) is not int or document["format_version"] != _FORMAT_VERSION:
        raise ValueError("unsupported capture plan format_version")
    unknown = document.keys() - _FIELDS
    if unknown:
        raise ValueError("unknown capture plan fields: " + ", ".join(sorted(unknown)))

    def resolve(key: str, required: bool = False) -> Path | None:
        value = document.get(key)
        if value is None and not required:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"capture plan {key} must be a non-empty path")
        resolved = (path.parent / value).resolve()
        if not resolved.is_file():
            raise ValueError(f"capture plan {key} file is missing: {resolved}")
        return resolved

    project = resolve("project", required=True)
    scenario = document.get("scenario")
    if not isinstance(scenario, str) or not scenario.strip():
        raise ValueError("capture plan scenario must be a non-empty string")
    arguments = document.get("adapter_arguments", {})
    if not isinstance(arguments, dict):
        raise ValueError("capture plan adapter_arguments must be an object")
    overrides = []
    for key, value in sorted(arguments.items()):
        if not key or "=" in key:
            raise ValueError("capture plan adapter argument names must be non-empty and exclude '='")
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            raise ValueError(f"capture plan adapter argument {key} must be a string or number")
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError(f"capture plan adapter argument {key} must be finite")
        overrides.append((key, str(value)))
    return CapturePlan(path, hashlib.sha256(raw).hexdigest(), project, scenario,
                       resolve("movie"), resolve("input_script"), tuple(overrides))
