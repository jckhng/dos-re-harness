"""Explicit local tool/environment overrides for portable execution plans."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re

from .evidence import sha256_file

_VARIABLE = re.compile(r"(?<!\$)\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def environment_key(name: str) -> str:
    return name.upper() if os.name == "nt" else name


def validate_environment(environment, unset_environment):
    if not isinstance(environment, dict) or any(
        not isinstance(k, str) or not k or "=" in k or "\0" in k
        or not isinstance(v, str) or "\0" in v for k, v in environment.items()
    ):
        raise ValueError("environment must contain valid string names and values")
    if not isinstance(unset_environment, list) or any(
        not isinstance(k, str) or not k or "=" in k or "\0" in k for k in unset_environment
    ):
        raise ValueError("unset_environment must contain valid variable names")
    assigned = [environment_key(k) for k in environment]
    removed = [environment_key(k) for k in unset_environment]
    if len(set(assigned)) != len(assigned) or len(set(removed)) != len(removed):
        raise ValueError("duplicate environment variable")
    if set(assigned) & set(removed):
        raise ValueError("cannot both set and unset an environment variable")


def expand_value(value: str, values: dict[str, str]) -> str:
    def replace(match):
        name = match.group(1)
        if name not in values:
            raise ValueError("unknown plan variable: " + name)
        return values[name]
    return _VARIABLE.sub(replace, value).replace("$${", "${")


def load_host_profile(path: Path | None) -> dict:
    if path is None:
        return dict(tools={}, values={}, environment={}, unset_environment=[], binding=None)
    path = path.resolve()
    document = json.loads(path.read_text(encoding="utf-8-sig"))
    fields = {"format_version", "tools", "values", "environment", "unset_environment"}
    if (not isinstance(document, dict) or set(document) - fields
            or type(document.get("format_version")) is not int or document["format_version"] != 1):
        raise ValueError("invalid host-profile version or fields")
    values = document.get("values", {})
    if (not isinstance(values, dict) or any(
        not isinstance(k, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k)
        or k in {"plan_dir", "profile_dir"} or not isinstance(v, str) or "\0" in v
        for k, v in values.items())):
        raise ValueError("invalid host-profile values")
    scope = {"profile_dir": str(path.parent)}
    values = {k: expand_value(v, scope) for k, v in values.items()}
    scope.update(values)
    tools = document.get("tools", {})
    if not isinstance(tools, dict):
        raise ValueError("host-profile tools must be an object")
    resolved_tools = {}
    for name, prefix in tools.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+", name)
                or not isinstance(prefix, list) or not prefix
                or any(not isinstance(v, str) or not v or "\0" in v for v in prefix)):
            raise ValueError("host-profile tools require nonempty argument arrays")
        prefix = [expand_value(v, scope) for v in prefix]
        if not Path(prefix[0]).is_absolute() and any(c in prefix[0] for c in ("/", "\\")):
            prefix[0] = str((path.parent / prefix[0]).resolve())
        resolved_tools[name] = prefix
    environment = document.get("environment", {})
    unset = document.get("unset_environment", [])
    validate_environment(environment, unset)
    return dict(tools=resolved_tools, values=scope,
                environment={k: expand_value(v, scope) for k, v in environment.items()},
                unset_environment=unset, binding=dict(path=str(path), sha256=sha256_file(path)))
