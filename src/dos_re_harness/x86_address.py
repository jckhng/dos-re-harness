"""Checked x86 segment ranges and the pinned DOSBox-X breakpoint encoding."""
from __future__ import annotations

from dataclasses import dataclass


DESCRIPTOR_BYTES = 8
LINEAR_ADDRESS_LIMIT = 0xffffffff
REAL_MODE_ALIAS_LIMIT = 0x100000


def _unsigned(value: int, maximum: int, name: str) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an integer in 0..{maximum:#x}")


def pack_segment_offset(segment: int, offset: int) -> int:
    """Pack two 16-bit components, never truncate a protected-mode EIP."""
    _unsigned(segment, 0xffff, "breakpoint segment")
    _unsigned(offset, 0xffff, "breakpoint offset")
    return (segment << 16) | offset


def real_mode_breakpoint(linear: int) -> int:
    """Encode a physical alias below 1 MiB; arm only while the CPU is in real mode.

    The backend resolves the address when inserting the breakpoint. This is not
    a selector calculation and must not be used after entering protected mode.
    """
    _unsigned(linear, REAL_MODE_ALIAS_LIMIT - 1, "real-mode breakpoint address")
    return pack_segment_offset(linear >> 4, linear & 15)


@dataclass(frozen=True)
class GdtSegment:
    selector: int
    base: int
    limit: int
    access: int
    default_32: bool

    def address(self, offset: int, size: int) -> int:
        """Resolve a nonempty, nonwrapping range; this does not translate paging."""
        _unsigned(offset, LINEAR_ADDRESS_LIMIT, "segment offset")
        _unsigned(size, LINEAR_ADDRESS_LIMIT + 1, "range size")
        if size == 0 or offset + size - 1 > self.limit:
            raise ValueError("Range exceeds the descriptor's segment limit")
        linear = self.base + offset
        if linear + size - 1 > LINEAR_ADDRESS_LIMIT:
            raise ValueError("Range wraps the 32-bit linear address space")
        return linear


def decode_gdt_segment(table: bytes, selector: int) -> GdtSegment:
    """Decode a present, expand-up legacy code/data descriptor.

    Pass only bytes within the captured GDTR limit. RPL is retained but does not
    change the table index. LDT, system, expand-down and long-mode descriptors
    reject. The caller must establish CPU mode, table identity and privileges.
    """
    _unsigned(selector, 0xffff, "selector")
    index = selector & ~7
    if selector & 4 or index == 0 or index + DESCRIPTOR_BYTES > len(table):
        raise ValueError("Expected a non-null selector within the supplied GDT")
    raw = table[index:index + DESCRIPTOR_BYTES]
    access = raw[5]
    if access & 0x90 != 0x90:
        raise ValueError("Segment must be present and describe code or data")
    if not access & 8 and access & 4:
        raise ValueError("Expand-down segments are not supported")
    if raw[6] & 0x20:
        raise ValueError("Long-mode descriptors are not supported")
    base = int.from_bytes(raw[2:4], "little") | raw[4] << 16 | raw[7] << 24
    limit = int.from_bytes(raw[:2], "little") | (raw[6] & 15) << 16
    if raw[6] & 0x80:
        limit = (limit << 12) | 0xfff
    return GdtSegment(selector, base, limit, access, bool(raw[6] & 0x40))
