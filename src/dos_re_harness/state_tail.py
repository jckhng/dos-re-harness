from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, List, Tuple

from .movie import load_movie
from .remote_capture import load_state_input_script


StateInputEvent = Tuple[int, bool, List[str]]


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _artifact(path: Path) -> dict[str, Any]:
    resolved = path.resolve()
    return {
        "path": str(resolved),
        "bytes": resolved.stat().st_size,
        "sha256": _sha256(resolved),
    }


def _events_by_value(
    events: list[StateInputEvent],
) -> dict[int, list[tuple[bool, list[str]]]]:
    grouped: dict[int, list[tuple[bool, list[str]]]] = {}
    for value, pressed, qcodes in events:
        grouped.setdefault(value, []).append((pressed, qcodes))
    return grouped


def _apply_events(
    held: set[str],
    events: list[tuple[bool, list[str]]],
) -> None:
    for pressed, qcodes in events:
        if pressed:
            held.update(qcodes)
        else:
            held.difference_update(qcodes)


def first_changed_input_value(
    previous_events: list[StateInputEvent],
    current_events: list[StateInputEvent],
) -> int | None:
    previous_by_value = _events_by_value(previous_events)
    current_by_value = _events_by_value(current_events)
    previous_held: set[str] = set()
    current_held: set[str] = set()
    for value in sorted(set(previous_by_value) | set(current_by_value)):
        _apply_events(previous_held, previous_by_value.get(value, []))
        _apply_events(current_held, current_by_value.get(value, []))
        if previous_held != current_held:
            return value
    return None


def _validate_segmented_address(value: str) -> None:
    parts = value.split(":")
    if len(parts) != 2:
        raise ValueError(
            "transition breakpoint must use SEGMENT:OFFSET syntax"
        )
    for part in parts:
        int(part, 0)


def _validate_bootstrap_movie(
    movie_path: Path,
    *,
    breakpoint: str,
    state_field: str,
) -> dict[str, Any]:
    movie = load_movie(movie_path)
    actions = movie["actions"]
    break_prefix = f"breakstate:{breakpoint}:{state_field}==1:"
    if not any(action.startswith(break_prefix) for action in actions):
        raise ValueError(
            f"bootstrap movie must stop at {state_field}==1 on {breakpoint}"
        )
    if f"clearbreak:{breakpoint}" not in actions:
        raise ValueError(
            f"bootstrap movie must clear breakpoint {breakpoint}"
        )
    return _artifact(movie_path)


def build_state_tail_plan(
    *,
    previous_script: Path,
    current_script: Path,
    snapshot: Path,
    checkpoint_value: int,
    end_value: int,
    breakpoint: str,
    state_field: str,
    bootstrap_movie: Path,
    capture_out: Path,
    maximum_hit_margin: int = 62,
    resume_next_linear: str | None = None,
    dump_segment: str = "ds",
    dump_offset: int = 0,
    dump_file: str = "remote_runtime_ds.bin",
    dump_size: int = 65536,
    transition_breakpoint: str | None = None,
    transition_out: Path | None = None,
    allow_existing_capture: bool = False,
    allow_existing_transition: bool = False,
) -> dict[str, Any]:
    if checkpoint_value < 0 or end_value < checkpoint_value:
        raise ValueError(
            "state tail requires 0 <= checkpoint_value <= end_value"
        )
    if maximum_hit_margin < 1:
        raise ValueError("maximum hit margin must be positive")
    if dump_segment not in {"ds", "ss"}:
        raise ValueError("dump segment must be ds or ss")
    if dump_offset < 0 or dump_size < 1:
        raise ValueError("dump offset and size must be non-negative")
    int(breakpoint, 0)
    selected_resume_next = resume_next_linear or hex(
        int(breakpoint, 0) + 3
    )
    int(selected_resume_next, 0)

    previous_path = previous_script.resolve()
    current_path = current_script.resolve()
    previous_metadata, previous_events = load_state_input_script(
        previous_path
    )
    current_metadata, current_events = load_state_input_script(current_path)
    for path, metadata in (
        (previous_path, previous_metadata),
        (current_path, current_metadata),
    ):
        configured_field = metadata.get("state_field")
        if configured_field is not None and configured_field != state_field:
            raise ValueError(
                f"{path}: state_field {configured_field!r} does not match "
                f"{state_field!r}"
            )
    first_changed = first_changed_input_value(
        previous_events,
        current_events,
    )
    if first_changed is not None and checkpoint_value > first_changed:
        raise ValueError(
            f"checkpoint {checkpoint_value} is after first changed input "
            f"value {first_changed}"
        )

    snapshot_path = snapshot.resolve()
    runtime_dump = snapshot_path / dump_file
    registers = snapshot_path / "remote_runtime_registers.json"
    if not runtime_dump.is_file():
        raise ValueError(f"resume dump is missing: {runtime_dump}")
    actual_dump_size = runtime_dump.stat().st_size
    if actual_dump_size != dump_size:
        raise ValueError(
            f"resume dump has {actual_dump_size} bytes; "
            f"expected {dump_size} bytes"
        )
    if not registers.is_file():
        raise ValueError(f"resume registers are missing: {registers}")

    movie_artifact = _validate_bootstrap_movie(
        bootstrap_movie.resolve(),
        breakpoint=breakpoint,
        state_field=state_field,
    )
    capture_path = capture_out.resolve()
    if capture_path.exists() and not allow_existing_capture:
        raise ValueError(f"capture output already exists: {capture_path}")
    if (transition_breakpoint is None) != (transition_out is None):
        raise ValueError(
            "transition breakpoint and output must be provided together"
        )
    transition_path = (
        transition_out.resolve()
        if transition_out is not None
        else None
    )
    if transition_path is not None:
        _validate_segmented_address(transition_breakpoint or "")
        if transition_path.exists() and not allow_existing_transition:
            raise ValueError(
                f"transition output already exists: {transition_path}"
            )

    values = list(range(checkpoint_value, end_value + 1))
    encoded_values = "+".join(str(value) for value in values)
    maximum_hits = end_value - checkpoint_value + maximum_hit_margin
    adapter_arguments = [
        (
            f"poke_file={dump_segment}:{dump_offset}:"
            f"{runtime_dump}"
        ),
        (
            "resume_checkpoint_script=checkpointstatescriptfile:"
            f"{breakpoint}:{state_field}:{encoded_values}:{maximum_hits}"
        ),
        f"resume_next_linear={selected_resume_next}",
        "checkpoint_vga=0",
    ]
    plan: dict[str, Any] = {
        "format_version": 1,
        "state_field": state_field,
        "first_changed_value": first_changed,
        "scripts": {
            "previous": _artifact(previous_path),
            "current": _artifact(current_path),
            "previous_metadata": previous_metadata,
            "current_metadata": current_metadata,
        },
        "snapshot": {
            "path": str(snapshot_path),
            "value": checkpoint_value,
            "runtime_dump": _artifact(runtime_dump),
            "registers": _artifact(registers),
        },
        "bootstrap_movie": movie_artifact,
        "capture": {
            "output": str(capture_path),
            "first_value": checkpoint_value,
            "last_value": end_value,
            "value_count": len(values),
            "maximum_hits": maximum_hits,
            "adapter_arguments": adapter_arguments,
        },
    }
    if transition_path is not None:
        final_snapshot = (
            capture_path
            / "checkpoints"
            / f"{state_field}-{end_value}"
        )
        plan["transition"] = {
            "output": str(transition_path),
            "breakpoint": transition_breakpoint,
            "snapshot": str(final_snapshot),
            "adapter_arguments": [
                (
                    f"poke_file={dump_segment}:{dump_offset}:"
                    f"{final_snapshot / dump_file}"
                ),
                (
                    "resume_checkpoint_script="
                    "checkpointstatescriptfile:"
                    f"{breakpoint}:{state_field}:{end_value}:"
                    f"{maximum_hit_margin}"
                ),
                f"resume_next_linear={selected_resume_next}",
                f"post_resume_break_segmented={transition_breakpoint}",
                "checkpoint_vga=0",
            ],
        }
    return plan
