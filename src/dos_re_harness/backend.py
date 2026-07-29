"""Backend capabilities and host-environment diagnostics."""

from __future__ import annotations

import importlib.util
import json
import platform
import shutil
from dataclasses import dataclass
from typing import Any

from .project import Project


CAPABILITIES = {
    "audio.capture",
    "cpu.halt",
    "cpu.registers.read",
    "cpu.registers.write",
    "execution.breakpoint-series",
    "execution.call-near",
    "input.keyboard",
    "memory.read",
    "memory.write",
    "screen.capture",
    "screen.sequence",
    "state.wait",
}


@dataclass(frozen=True)
class Diagnostic:
    name: str
    status: str
    detail: str


def declared_capabilities(project: Project) -> set[str]:
    adapter = project.data.get("capture_adapter", {})
    values = adapter.get("capabilities", [])
    if not isinstance(values, list) or not all(isinstance(value, str) for value in values):
        raise ValueError("capture_adapter.capabilities must be a string array")
    return set(values)


def validate_capabilities(project: Project) -> list[str]:
    declared = declared_capabilities(project)
    errors = [
        f"capture_adapter.capabilities: unknown capability {value}"
        for value in sorted(declared - CAPABILITIES)
    ]
    scenarios_path = project.referenced_path("scenarios")
    scenarios = json.loads(scenarios_path.read_text(encoding="utf-8-sig"))["scenarios"]
    for name, scenario in scenarios.items():
        values = scenario.get("requires", [])
        if not isinstance(values, list) or not all(
            isinstance(value, str) for value in values
        ):
            continue
        required = set(values)
        unknown = required - CAPABILITIES
        errors.extend(
            f"scenario {name}: unknown capability {value}"
            for value in sorted(unknown)
        )
        missing = required - declared
        if missing:
            errors.append(
                f"scenario {name}: backend lacks {', '.join(sorted(missing))}"
            )
    return errors


def diagnose(project: Project) -> list[Diagnostic]:
    adapter = project.data.get("capture_adapter", {})
    command = adapter.get("command", [])
    executable = command[0] if command else ""
    diagnostics = [
        Diagnostic("host", "ok", f"{platform.system()} {platform.release()}"),
        Diagnostic("python", "ok", platform.python_version()),
        Diagnostic(
            "capture-command",
            "ok" if executable and shutil.which(executable) else "missing",
            executable or "not declared",
        ),
        Diagnostic(
            "dbxdebug",
            "optional" if importlib.util.find_spec("dbxdebug") is None else "ok",
            "optional protocol client; custom extensions remain supported",
        ),
        Diagnostic(
            "pillow",
            "optional" if importlib.util.find_spec("PIL") is None else "ok",
            "needed only for PNG visual comparison",
        ),
    ]
    if adapter.get("type") == "powershell-wsl-remotedebug":
        diagnostics.append(
            Diagnostic(
                "wsl",
                "ok" if shutil.which("wsl.exe") else "missing",
                "required by powershell-wsl-remotedebug",
            )
        )
    return diagnostics
