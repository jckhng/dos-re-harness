"""Declared file identities shared by execution and evidence preflight."""
from __future__ import annotations

from pathlib import Path
import re

from .evidence import sha256_file


def binding_paths(bindings: list[dict], base: Path) -> list[tuple[Path, str]]:
    if not isinstance(bindings, list):
        raise ValueError("inputs must be a list of file bindings")
    records = []
    seen = set()
    for binding in bindings:
        if (not isinstance(binding, dict) or set(binding) != {"path", "sha256"}
                or not isinstance(binding["path"], str) or not binding["path"]
                or not isinstance(binding["sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", binding["sha256"])):
            raise ValueError("file binding requires path and lowercase sha256")
        path = (base / binding["path"]).resolve()
        if path in seen:
            raise ValueError("duplicate bound path: " + str(path))
        seen.add(path)
        records.append((path, binding["sha256"]))
    return records


def inspect_bindings(bindings: list[dict], base: Path) -> list[dict]:
    records = []
    for path, expected in binding_paths(bindings, base):
        actual = sha256_file(path) if path.is_file() else None
        records.append(dict(path=str(path), sha256=expected, actual_sha256=actual,
                            status="missing" if actual is None else
                            "current" if actual == expected else "stale"))
    return records
