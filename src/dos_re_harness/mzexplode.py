"""Auditable orchestration for unpacking DOS MZ executables with mzexplode."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


_DISTRIBUTION_NAME = re.compile(r"^[A-Za-z0-9_.-]+$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_WINDOWS_PATH = re.compile(r"^([A-Za-z]):[\\/](.*)$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    return {
        "path": str(path.resolve()),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def windows_path_to_wsl(path: Path) -> str:
    value = str(path)
    match = _WINDOWS_PATH.match(value)
    if match is None:
        raise ValueError(f"WSL execution requires a Windows drive path, got: {value}")
    drive = match.group(1).lower()
    remainder = match.group(2).replace("\\", "/")
    return f"/mnt/{drive}/{remainder}"


def build_mzexplode_command(
    *,
    tool: str,
    input_path: Path,
    output_path: Path,
    wsl_distribution: str | None = None,
) -> list[str]:
    if not tool:
        raise ValueError("mzexplode tool path must not be empty")
    if wsl_distribution is None:
        return [tool, str(input_path), str(output_path)]
    if not _DISTRIBUTION_NAME.fullmatch(wsl_distribution):
        raise ValueError(
            f"unsupported WSL distribution name: {wsl_distribution!r}"
        )
    if not tool.startswith("/"):
        raise ValueError("WSL mzexplode tool path must be absolute")
    return [
        "wsl.exe",
        "--distribution",
        wsl_distribution,
        "--exec",
        tool,
        windows_path_to_wsl(input_path),
        windows_path_to_wsl(output_path),
    ]


def _native_tool_record(tool: str) -> dict[str, Any]:
    candidate = Path(tool)
    resolved = candidate.resolve() if candidate.is_file() else None
    if resolved is None:
        located = shutil.which(tool)
        resolved = Path(located).resolve() if located else None
    if resolved is None or not resolved.is_file():
        raise OSError(f"missing mzexplode tool: {tool}")
    return {
        "execution": "native",
        "path": str(resolved),
        "sha256": sha256_file(resolved),
    }


def _wsl_tool_record(tool: str, distribution: str) -> dict[str, Any]:
    result = subprocess.run(
        [
            "wsl.exe",
            "--distribution",
            distribution,
            "--exec",
            "sha256sum",
            tool,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise OSError(f"failed to hash WSL mzexplode tool: {detail}")
    fields = result.stdout.strip().split()
    if not fields or not _SHA256.fullmatch(fields[0]):
        raise OSError(f"unexpected sha256sum output for WSL mzexplode: {result.stdout!r}")
    return {
        "execution": "wsl",
        "distribution": distribution,
        "path": tool,
        "sha256": fields[0].lower(),
    }


def _require_mz(path: Path, label: str) -> None:
    if not path.is_file():
        raise OSError(f"{label} MZ file is missing: {path}")
    with path.open("rb") as handle:
        magic = handle.read(2)
    if magic != b"MZ":
        raise ValueError(f"{label} is not an MZ executable: {path}")


def unpack_mz(
    *,
    input_path: Path,
    output_path: Path,
    tool: str,
    wsl_distribution: str | None = None,
    manifest_path: Path | None = None,
    force: bool = False,
) -> Path:
    source = input_path.resolve()
    output = output_path.resolve()
    manifest = (
        manifest_path.resolve()
        if manifest_path is not None
        else output.with_name(output.name + ".mzexplode.json")
    )
    _require_mz(source, "input")
    if output == source:
        raise ValueError("mzexplode output must differ from its input")
    if manifest in {source, output}:
        raise ValueError("mzexplode manifest must differ from input and output")
    if output.exists() and not force:
        raise ValueError(f"refusing to overwrite mzexplode output: {output}")
    if manifest.exists() and not force:
        raise ValueError(f"refusing to overwrite mzexplode manifest: {manifest}")
    if force:
        if output.exists():
            output.unlink()
        if manifest.exists():
            manifest.unlink()

    output.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    tool_record = (
        _native_tool_record(tool)
        if wsl_distribution is None
        else _wsl_tool_record(tool, wsl_distribution)
    )
    command = build_mzexplode_command(
        tool=tool,
        input_path=source,
        output_path=output,
        wsl_distribution=wsl_distribution,
    )
    result = subprocess.run(command, check=False)
    if result.returncode != 0:
        raise OSError(f"mzexplode failed with exit code {result.returncode}")
    _require_mz(output, "output")

    document = {
        "format_version": 1,
        "operation": "mzexplode",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "command": command,
        "exit_code": result.returncode,
        "tool": tool_record,
        "input": file_record(source),
        "output": file_record(output),
    }
    manifest.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest
