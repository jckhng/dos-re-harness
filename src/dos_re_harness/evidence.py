"""Auditable manifests for original-binary capture artifacts."""

from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .project import Project, load_scenarios


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def file_record(path: Path) -> dict[str, Any]:
    return {
        "path": path.name,
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def backend_record(project: Project) -> dict[str, Any] | None:
    adapter = project.data.get("capture_adapter", {})
    if not isinstance(adapter, dict):
        return None
    lock_value = adapter.get("backend_lock")
    if not isinstance(lock_value, str):
        return None

    lock_path = project.resolve(lock_value)
    lock = json.loads(lock_path.read_text(encoding="utf-8-sig"))
    if not isinstance(lock, dict):
        raise ValueError(f"{lock_path}: backend lock must be an object")
    patch = lock.get("patch")
    if not isinstance(patch, dict) or not isinstance(patch.get("path"), str):
        raise ValueError(f"{lock_path}: backend lock patch path is missing")
    patch_path = (lock_path.parent / patch["path"]).resolve()
    actual_patch_sha256 = sha256_file(patch_path)
    expected_patch_sha256 = patch.get("sha256")
    if actual_patch_sha256 != expected_patch_sha256:
        raise ValueError(
            f"{patch_path}: expected sha256 {expected_patch_sha256}, "
            f"found {actual_patch_sha256}"
        )
    return {
        "lock": {
            "path": str(lock_path),
            "sha256": sha256_file(lock_path),
        },
        "upstream": lock.get("upstream"),
        "patch": {
            "path": str(patch_path),
            "sha256": actual_patch_sha256,
        },
        "license": lock.get("license"),
    }


def mutable_baseline(project: Project) -> list[dict[str, Any]]:
    specimen = project.data.get("specimen", {})
    if not isinstance(specimen, dict):
        return []
    root_value = specimen.get("root")
    mutable_files = specimen.get("mutable_files", [])
    if not isinstance(root_value, str) or not isinstance(mutable_files, list):
        return []
    root = project.resolve(root_value)
    records: list[dict[str, Any]] = []
    for value in mutable_files:
        if not isinstance(value, str):
            continue
        path = (root / value).resolve()
        try:
            path.relative_to(root)
        except ValueError as exc:
            raise ValueError(
                f"mutable file escapes specimen root: {value}"
            ) from exc
        record: dict[str, Any] = {"path": value, "present": path.is_file()}
        if path.is_file():
            record["bytes"] = path.stat().st_size
            record["sha256"] = sha256_file(path)
        records.append(record)
    return records


def git_commit(path: Path) -> str | None:
    try:
        return subprocess.check_output(
            [
                "git",
                "-c",
                f"safe.directory={path.as_posix()}",
                "-C",
                str(path),
                "rev-parse",
                "HEAD",
            ],
            text=True,
            stderr=subprocess.DEVNULL,
        ).strip()
    except (OSError, subprocess.CalledProcessError):
        return None


def write_evidence_manifest(
    project: Project,
    scenario: str,
    out_dir: Path,
    command: list[str],
    exit_code: int,
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    schema_path = project.referenced_path("runtime.state_schema")
    screens_path = project.referenced_path("runtime.screen_signatures")
    scenarios_path = project.referenced_path("scenarios")
    scenario_document = load_scenarios(project).get(scenario, {})
    input_movie = scenario_document.get("input_movie")
    specimen = project.data.get("specimen", {})
    specimen_manifest: dict[str, Any] | None = None
    if isinstance(specimen, dict) and isinstance(specimen.get("hash_manifest"), str):
        hash_path = project.resolve(specimen["hash_manifest"])
        specimen_manifest = {
            "path": str(hash_path),
            "sha256": sha256_file(hash_path) if hash_path.is_file() else None,
            "mutable_files": specimen.get("mutable_files", []),
        }

    manifest_path = out_dir / "harness_manifest.json"
    artifacts = [
        file_record(path)
        for path in sorted(out_dir.iterdir())
        if path.is_file() and path != manifest_path
    ]
    contracts = {
        "state_schema": {
            "path": str(schema_path),
            "sha256": sha256_file(schema_path),
        },
        "screen_signatures": {
            "path": str(screens_path),
            "sha256": sha256_file(screens_path),
        },
        "scenarios": {
            "path": str(scenarios_path),
            "sha256": sha256_file(scenarios_path),
        },
    }
    if isinstance(input_movie, str):
        movie_path = project.resolve(input_movie)
        contracts["input_movie"] = {
            "path": str(movie_path),
            "sha256": sha256_file(movie_path),
        }

    adapter = project.data.get("capture_adapter", {})
    configuration = (
        adapter.get("configuration", {}) if isinstance(adapter, dict) else {}
    )
    runtime = project.data.get("runtime", {})
    capture_selection = {
        key: runtime[key]
        for key in (
            "dump_segment",
            "dump_size",
            "vga_address",
            "vga_width",
            "vga_height",
            "framebuffer_encoding",
        )
        if isinstance(runtime, dict) and key in runtime
    }

    document = {
        "format_version": 1,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "project": {
            "id": project.data["id"],
            "path": str(project.path),
            "sha256": sha256_file(project.path),
        },
        "scenario": scenario,
        "command": command,
        "exit_code": exit_code,
        "git_commit": git_commit(project.root),
        "contracts": contracts,
        "backend": backend_record(project),
        "capture": {
            "configuration": configuration,
            "selection": capture_selection,
            "mutable_baseline": mutable_baseline(project),
        },
        "specimen": specimen_manifest,
        "artifacts": artifacts,
    }
    manifest_path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest_path
