"""Stable indexes for artifacts captured at breakpoint_hit-N checkpoints."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Iterable


CHECKPOINT_PATTERN = re.compile(r"^breakpoint_hit-(\d+)$")
REGISTER_METADATA_NAME = "remote_runtime_registers.json"
SUMMARY_NAME = "capture_summary.json"


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _declared_hits(capture: Path) -> list[int] | None:
    summary_path = capture / SUMMARY_NAME
    if not summary_path.is_file():
        return None
    document = json.loads(summary_path.read_text(encoding="utf-8"))
    break_state = document.get("break_state")
    if not isinstance(break_state, dict):
        return None
    series = break_state.get("post_resume_breakpoint_series")
    if not isinstance(series, dict):
        series = break_state.get("startup_breakpoint_series")
    if not isinstance(series, dict):
        return None
    hits = series.get("hits")
    if not isinstance(hits, list) or not all(isinstance(hit, int) for hit in hits):
        return None
    return [int(hit) for hit in hits]


def _checkpoint_paths(capture: Path) -> list[tuple[int, Path]]:
    checkpoint_root = capture / "checkpoints"
    paths: list[tuple[int, Path]] = []
    if checkpoint_root.is_dir():
        for path in checkpoint_root.iterdir():
            match = CHECKPOINT_PATTERN.fullmatch(path.name)
            if path.is_dir() and match:
                paths.append((int(match.group(1)), path))
    paths.sort(key=lambda item: item[0])
    if not paths:
        raise ValueError(
            f"{capture}: no checkpoints/breakpoint_hit-N directories found"
        )
    hits = [hit for hit, _ in paths]
    if len(hits) != len(set(hits)):
        raise ValueError(f"{capture}: duplicate breakpoint checkpoint hit")
    return paths


def index_checkpoint_series(
    capture: Path,
    *,
    artifact: str,
    offset: int = 0,
    length: int | None = None,
    registers: Iterable[str] = (),
    expected_hits: Iterable[int] | None = None,
    expected_hit_count: int | None = None,
) -> dict[str, Any]:
    """Index and hash one artifact slice across breakpoint checkpoints."""

    capture = capture.resolve()
    if offset < 0:
        raise ValueError("artifact slice offset must not be negative")
    if length is not None and length < 0:
        raise ValueError("artifact slice length must not be negative")
    artifact_path = Path(artifact)
    if artifact_path.is_absolute() or ".." in artifact_path.parts:
        raise ValueError("artifact must be a checkpoint-relative path")
    register_names = list(dict.fromkeys(str(name) for name in registers))
    paths = _checkpoint_paths(capture)
    hits = [hit for hit, _ in paths]
    declared_hits = _declared_hits(capture)
    if expected_hits is not None and expected_hit_count is not None:
        raise ValueError(
            "expected_hits and expected_hit_count are mutually exclusive"
        )
    if expected_hit_count is not None:
        if expected_hit_count < 1:
            raise ValueError("expected_hit_count must be positive")
        required_hits = list(range(1, expected_hit_count + 1))
    elif expected_hits is not None:
        required_hits = [int(hit) for hit in expected_hits]
    else:
        required_hits = declared_hits
    if required_hits is not None and hits != required_hits:
        raise ValueError(
            f"{capture}: checkpoint hits {hits} do not match expected {required_hits}"
        )

    checkpoints = []
    for hit, checkpoint in paths:
        path = checkpoint / artifact_path
        if not path.is_file():
            raise ValueError(f"{checkpoint}: missing artifact {artifact}")
        size = path.stat().st_size
        end = size if length is None else offset + length
        if offset > size or end > size:
            raise ValueError(
                f"{path}: slice {offset}:{end} exceeds artifact size {size}"
            )
        with path.open("rb") as stream:
            stream.seek(offset)
            sliced = stream.read(end - offset)
        selected_registers: dict[str, int] = {}
        if register_names:
            metadata_path = checkpoint / REGISTER_METADATA_NAME
            if not metadata_path.is_file():
                raise ValueError(f"{checkpoint}: missing {REGISTER_METADATA_NAME}")
            metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
            values = metadata.get("registers")
            if not isinstance(values, dict):
                raise ValueError(f"{metadata_path}: registers must be an object")
            for name in register_names:
                value = values.get(name)
                if not isinstance(value, int):
                    raise ValueError(
                        f"{metadata_path}: register {name!r} is missing or invalid"
                    )
                selected_registers[name] = int(value)
        checkpoints.append(
            {
                "hit": hit,
                "path": checkpoint.relative_to(capture).as_posix(),
                "artifact": {
                    "path": artifact_path.as_posix(),
                    "size": size,
                    "sha256": _sha256_file(path),
                },
                "slice": {
                    "offset": offset,
                    "length": len(sliced),
                    "sha256": _sha256_bytes(sliced),
                },
                "registers": selected_registers,
            }
        )

    encoded = json.dumps(
        checkpoints,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return {
        "format_version": 1,
        "capture": str(capture),
        "artifact": artifact_path.as_posix(),
        "slice": {"offset": offset, "length": length},
        "register_names": register_names,
        "declared_hits": declared_hits,
        "expected_hit_count": expected_hit_count,
        "hit_count": len(hits),
        "hits": hits,
        "series_sha256": _sha256_bytes(encoded),
        "checkpoints": checkpoints,
    }
