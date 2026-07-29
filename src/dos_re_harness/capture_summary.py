"""Compact, token-efficient summaries of remote runtime captures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


SUMMARY_NAME = "capture_summary.json"
REGISTER_METADATA_NAME = "remote_runtime_registers.json"


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _canonical_sha256(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _compact_mapping(
    value: Any,
    *,
    prefix: str,
    maximum_encoded_size: int = 4096,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    encoded = _canonical_bytes(value)
    if len(encoded) <= maximum_encoded_size:
        return {prefix: value}
    return {
        f"{prefix}_field_count": len(value),
        f"{prefix}_sha256": hashlib.sha256(encoded).hexdigest(),
    }


def _compact_break_state(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    compact = {}
    for key, item in value.items():
        if key in {"input_script", "state"}:
            continue
        if key == "input_script_source" and item == "None":
            compact[str(key)] = None
            continue
        if key == "post_resume_breakpoint_series" and isinstance(item, dict):
            series = {
                str(series_key): series_value
                for series_key, series_value in item.items()
                if series_key != "checkpoints"
            }
            checkpoints = item.get("checkpoints")
            series["checkpoint_count"] = (
                len(checkpoints) if isinstance(checkpoints, list) else 0
            )
            compact[str(key)] = series
        else:
            compact[str(key)] = item
    input_script = value.get("input_script")
    if isinstance(input_script, list) and input_script:
        compact["input_script_event_count"] = len(input_script)
        compact["input_script_sha256"] = _canonical_sha256(input_script)
    compact.update(_compact_mapping(value.get("state"), prefix="state"))
    return compact


def _compact_state_checkpoint(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"invalid_record_sha256": _canonical_sha256(value)}
    compact = {
        str(key): item
        for key, item in value.items()
        if key != "state"
    }
    state = value.get("state")
    if isinstance(state, dict):
        compact["state_field_count"] = len(state)
        compact["state_sha256"] = _canonical_sha256(state)
    return compact


def _resolve_artifact(capture_dir: Path, value: Any) -> Path | None:
    if not isinstance(value, str) or not value:
        return None
    declared = Path(value)
    candidates = (
        declared,
        capture_dir / declared,
        capture_dir / declared.name,
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate.resolve()
    return None


def _display_path(capture_dir: Path, path: Path) -> str:
    try:
        return path.relative_to(capture_dir.resolve()).as_posix()
    except ValueError:
        return str(path)


def build_capture_summary(capture_dir: Path) -> dict[str, Any]:
    capture_dir = capture_dir.resolve()
    metadata_path = capture_dir / REGISTER_METADATA_NAME
    if not metadata_path.is_file():
        raise ValueError(f"capture register metadata is missing: {metadata_path}")
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    if not isinstance(metadata, dict):
        raise ValueError("capture register metadata must be a JSON object")

    checkpoints = metadata.get("state_checkpoints")
    compact_checkpoints = (
        [_compact_state_checkpoint(item) for item in checkpoints]
        if isinstance(checkpoints, list)
        else []
    )
    artifacts = []
    for field in (
        "dump",
        "low_memory_dump",
        "screenshot",
        "vga_dump",
        "vga_pgm",
    ):
        path = _resolve_artifact(capture_dir, metadata.get(field))
        if path is None:
            continue
        artifacts.append(
            {
                "kind": field,
                "path": _display_path(capture_dir, path),
                "size": path.stat().st_size,
                "sha256": _file_sha256(path),
            }
        )

    break_state = _compact_break_state(metadata.get("break_state"))
    post_resume_hits = 0
    if isinstance(break_state, dict):
        series = break_state.get("post_resume_breakpoint_series")
        if isinstance(series, dict) and isinstance(series.get("hits"), list):
            post_resume_hits = len(series["hits"])

    return {
        "format_version": 1,
        "capture": str(capture_dir),
        "stop": metadata.get("stop"),
        "registers": metadata.get("registers", {}),
        "wait_state": metadata.get("wait_state"),
        "break_state": break_state,
        "state_checkpoints": compact_checkpoints,
        "counts": {
            "state_checkpoints": len(compact_checkpoints),
            "post_resume_hits": post_resume_hits,
        },
        "artifacts": artifacts,
        "source": {
            "path": REGISTER_METADATA_NAME,
            "size": metadata_path.stat().st_size,
            "sha256": _file_sha256(metadata_path),
        },
    }


def write_capture_summary(
    capture_dir: Path,
    output_path: Path | None = None,
) -> Path:
    capture_dir = capture_dir.resolve()
    output = (
        output_path.resolve()
        if output_path is not None
        else capture_dir / SUMMARY_NAME
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(output.name + ".partial")
    temporary.write_text(
        json.dumps(build_capture_summary(capture_dir), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )
    temporary.replace(output)
    return output


def format_capture_summary_line(summary: dict[str, Any]) -> str:
    registers = summary.get("registers")
    registers = registers if isinstance(registers, dict) else {}
    counts = summary.get("counts")
    counts = counts if isinstance(counts, dict) else {}
    stop = summary.get("stop")
    cs = int(registers.get("cs", 0))
    eip = int(registers.get("eip", 0))
    state_checkpoints = int(counts.get("state_checkpoints", 0))
    post_resume_hits = int(counts.get("post_resume_hits", 0))
    return (
        f"CAPTURE stop={stop} cs={cs:04x} eip={eip:08x} "
        f"state_checkpoints={state_checkpoints} "
        f"post_resume_hits={post_resume_hits}"
    )
