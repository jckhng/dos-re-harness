"""Versioned, state-gated input movie files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def load_movie(path: Path) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict) or document.get("format_version") != 1:
        raise ValueError(f"{path}: input movie requires format_version 1")
    actions = document.get("actions")
    if not isinstance(actions, list) or not all(isinstance(item, str) for item in actions):
        raise ValueError(f"{path}: input movie actions must be strings")
    if not actions:
        raise ValueError(f"{path}: input movie must contain at least one action")
    return document


def scenario_actions(project_root: Path, scenario: dict[str, Any]) -> list[str]:
    inline = scenario.get("startup_actions", [])
    movie_path = scenario.get("input_movie")
    if movie_path is not None and inline:
        raise ValueError("scenario cannot define both input_movie and startup_actions")
    if movie_path is not None:
        path = Path(movie_path)
        resolved = path if path.is_absolute() else (project_root / path).resolve()
        return list(load_movie(resolved)["actions"])
    if not isinstance(inline, list) or not all(isinstance(item, str) for item in inline):
        raise ValueError("scenario startup_actions must be strings")
    return list(inline)
