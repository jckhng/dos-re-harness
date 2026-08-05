"""Extract deterministic register-pair streams from breakpoint captures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any


REGISTER_METADATA_NAME = "remote_runtime_registers.json"


def _encoded_width(mask: int) -> int:
    if mask < 0:
        raise ValueError("register masks must not be negative")
    return max(1, (mask.bit_length() + 7) // 8)


def extract_register_pair_trace(
    capture: Path,
    *,
    address_register: str,
    value_register: str,
    address_mask: int = 0xFF,
    value_mask: int = 0xFF,
) -> dict[str, Any]:
    """Extract masked register pairs from breakpoint_hit-N checkpoints."""

    capture = capture.resolve()
    checkpoints = capture / "checkpoints"
    paths = sorted(
        checkpoints.glob("breakpoint_hit-*"),
        key=lambda path: int(path.name.rsplit("-", 1)[1]),
    )
    if not paths:
        raise ValueError(
            f"{capture}: no checkpoints/breakpoint_hit-N directories found"
        )
    address_width = _encoded_width(address_mask)
    value_width = _encoded_width(value_mask)
    encoded = bytearray()
    writes = []
    for path in paths:
        metadata_path = path / REGISTER_METADATA_NAME
        if not metadata_path.is_file():
            raise ValueError(
                f"{path}: missing {REGISTER_METADATA_NAME}"
            )
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
        registers = document.get("registers")
        if not isinstance(registers, dict):
            raise ValueError(f"{metadata_path}: registers must be an object")
        for name in (address_register, value_register):
            if not isinstance(registers.get(name), int):
                raise ValueError(
                    f"{metadata_path}: register {name!r} is missing or invalid"
                )
        hit = int(path.name.rsplit("-", 1)[1])
        address = int(registers[address_register]) & address_mask
        value = int(registers[value_register]) & value_mask
        writes.append({"hit": hit, "address": address, "value": value})
        encoded.extend(address.to_bytes(address_width, "little"))
        encoded.extend(value.to_bytes(value_width, "little"))
    return {
        "format_version": 1,
        "capture": str(capture),
        "address_register": address_register,
        "value_register": value_register,
        "address_mask": address_mask,
        "value_mask": value_mask,
        "write_count": len(writes),
        "stream_sha256": hashlib.sha256(encoded).hexdigest(),
        "writes": writes,
    }
