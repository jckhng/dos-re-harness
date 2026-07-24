"""Project and scenario manifests for DOS differential-reimplementation work."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .schema import load_schema, parse_int
from .screens import ScreenClassifier
from .movie import scenario_actions


@dataclass(frozen=True)
class Project:
    path: Path
    data: dict[str, Any]

    @property
    def root(self) -> Path:
        return self.path.parent

    def resolve(self, value: str) -> Path:
        path = Path(value)
        return path if path.is_absolute() else (self.root / path).resolve()

    def referenced_path(self, dotted_key: str) -> Path:
        value: Any = self.data
        for part in dotted_key.split("."):
            if not isinstance(value, dict) or part not in value:
                raise ValueError(f"{self.path}: missing {dotted_key}")
            value = value[part]
        if not isinstance(value, str) or not value:
            raise ValueError(f"{self.path}: {dotted_key} must be a path string")
        return self.resolve(value)


def load_project(path: Path) -> Project:
    resolved = path.resolve()
    document = json.loads(resolved.read_text(encoding="utf-8-sig"))
    if not isinstance(document, dict):
        raise ValueError(f"{path}: project manifest must be an object")
    if document.get("format_version") != 1:
        raise ValueError(f"{path}: unsupported or missing format_version")
    if not isinstance(document.get("id"), str) or not document["id"]:
        raise ValueError(f"{path}: project id must be a non-empty string")
    return Project(resolved, document)


def load_scenarios(project: Project) -> dict[str, dict[str, Any]]:
    path = project.referenced_path("scenarios")
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    scenarios = document.get("scenarios")
    if not isinstance(scenarios, dict):
        raise ValueError(f"{path}: scenarios must be an object")
    return scenarios


def validate_project(project: Project) -> list[str]:
    errors: list[str] = []
    required_paths = [
        "runtime.state_schema",
        "runtime.screen_signatures",
        "scenarios",
    ]
    for key in required_paths:
        try:
            path = project.referenced_path(key)
            if not path.is_file():
                errors.append(f"{key}: missing file {path}")
        except ValueError as exc:
            errors.append(str(exc))

    try:
        load_schema(project.referenced_path("runtime.state_schema"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"runtime.state_schema: {exc}")
    try:
        ScreenClassifier.load(project.referenced_path("runtime.screen_signatures"))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"runtime.screen_signatures: {exc}")
    try:
        scenarios = load_scenarios(project)
        for name, scenario in scenarios.items():
            if not isinstance(scenario, dict):
                errors.append(f"scenario {name}: must be an object")
                continue
            try:
                scenario_actions(project.root, scenario)
            except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
                errors.append(f"scenario {name}: {exc}")
            requires = scenario.get("requires", [])
            if not isinstance(requires, list) or not all(
                isinstance(value, str) for value in requires
            ):
                errors.append(f"scenario {name}: requires must be strings")
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"scenarios: {exc}")

    runtime = project.data.get("runtime", {})
    try:
        parse_int(runtime.get("dump_size"))
    except (TypeError, ValueError) as exc:
        errors.append(f"runtime.dump_size: {exc}")
    if runtime.get("dump_segment") not in {"ds", "ss"}:
        errors.append("runtime.dump_segment: expected ds or ss")
    adapter = project.data.get("capture_adapter", {})
    if isinstance(adapter, dict):
        configuration = adapter.get("configuration", {})
        if not isinstance(configuration, dict):
            errors.append("capture_adapter.configuration: expected object")
        backend_lock = adapter.get("backend_lock")
        if backend_lock is not None:
            if not isinstance(backend_lock, str) or not backend_lock:
                errors.append("capture_adapter.backend_lock: expected path string")
            elif not project.resolve(backend_lock).is_file():
                errors.append(
                    "capture_adapter.backend_lock: missing file "
                    f"{project.resolve(backend_lock)}"
                )
    try:
        from .backend import validate_capabilities

        errors.extend(validate_capabilities(project))
    except (OSError, ValueError, TypeError, json.JSONDecodeError) as exc:
        errors.append(f"capture_adapter.capabilities: {exc}")
    return errors
