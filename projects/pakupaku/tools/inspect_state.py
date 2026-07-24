#!/usr/bin/env python3
"""Decode confirmed DS globals and far-pointer-backed entity state."""

from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path


def u8(data: bytes, offset: int) -> int:
    return data[offset]


def u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def far_pointer(data: bytes, offset: int) -> tuple[int, int]:
    return u16(data, offset), u16(data, offset + 2)


def far_to_dump_offset(
    pointer: tuple[int, int], dump_segment: int, dump_size: int
) -> int:
    offset, segment = pointer
    linear = segment * 16 + offset
    relative = linear - dump_segment * 16
    if relative < 0 or relative >= dump_size:
        raise ValueError(
            f"far pointer {segment:04x}:{offset:04x} is outside the captured range"
        )
    return relative


def decode_position(data: bytes, dump_segment: int, pointer_offset: int) -> dict:
    pointer = far_pointer(data, pointer_offset)
    record = far_to_dump_offset(pointer, dump_segment, len(data))
    return {
        "position_far": f"{pointer[1]:04x}:{pointer[0]:04x}",
        "position_capture_offset": record,
        "x": u16(data, record),
        "y": u16(data, record + 2),
        "sprite": u16(data, record + 4),
        "previous_x": u16(data, record + 10),
        "previous_y": u16(data, record + 12),
    }


def decode_state(data: bytes, dump_segment: int) -> dict:
    state = {
        "rng_state": u32(data, 0x6DC),
        "score": u32(data, 0x6F0),
        "high_score": u32(data, 0x6F4),
        "lives": u16(data, 0x7AC),
        "level": u16(data, 0x7AE),
        "level_index": u16(data, 0x7B0),
        "pellets_remaining": u16(data, 0x7B2),
        "ghost_mode": u16(data, 0x7B4),
        "ghost_score": u16(data, 0x7B6),
        "ghost_mode_phase": u16(data, 0x7B8),
        "ghost_mode_ticks": u16(data, 0x7BA),
        "frightened_ticks": u16(data, 0x7C0),
        "animation_phase": u16(data, 0x7C2),
        "update_divisor": u16(data, 0x7CC),
        "player": {
            **decode_position(data, dump_segment, 0xBA2),
            "direction": u8(data, 0xBA8),
            "requested_direction": u8(data, 0xBA9),
        },
        "ghosts": [],
    }

    wrapper_pointer = far_pointer(data, 0xBBC)
    seen: set[tuple[int, int]] = set()
    while wrapper_pointer != (0, 0):
        if wrapper_pointer in seen:
            raise ValueError("cycle in ghost linked list")
        seen.add(wrapper_pointer)
        wrapper = far_to_dump_offset(wrapper_pointer, dump_segment, len(data))
        position = decode_position(data, dump_segment, wrapper + 2)
        state["ghosts"].append(
            {
                "far": f"{wrapper_pointer[1]:04x}:{wrapper_pointer[0]:04x}",
                "capture_offset": wrapper,
                **position,
                "direction": u16(data, wrapper + 8),
                "sprite_family": u16(data, wrapper + 14),
                "personality": u16(data, wrapper + 16),
                "mode": u16(data, wrapper + 18),
                "mode_ticks": u16(data, wrapper + 22),
                "release_ticks": u16(data, wrapper + 24),
                "target_x": u16(data, wrapper + 26),
                "target_y": u16(data, wrapper + 28),
                "in_pen": u8(data, wrapper + 31),
            }
        )
        wrapper_pointer = far_pointer(data, wrapper + 32)
    return state


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("capture", type=Path)
    args = parser.parse_args()
    registers = json.loads(
        (args.capture / "remote_runtime_registers.json").read_text(encoding="utf-8")
    )
    dump_segment = int(registers["dump_segment_value"])
    state = decode_state(
        (args.capture / "remote_runtime_ds.bin").read_bytes(), dump_segment
    )
    print(json.dumps(state, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
