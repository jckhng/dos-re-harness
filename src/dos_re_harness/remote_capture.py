#!/usr/bin/env python3
"""Control a remotedebug DOSBox-X instance and capture runtime evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import select
import socket
import struct
import sys
import threading
import time
import wave
import zlib
from pathlib import Path
from typing import Any, Callable

from .capture_summary import write_capture_summary
from .schema import Field, load_schema
from .screens import ScreenClassifier


class RspClient:
    def __init__(self, host: str, port: int, timeout: float) -> None:
        deadline = time.time() + timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((host, port), 1.0)
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.1)
        else:
            raise RuntimeError(f"GDB port {port} did not open: {last_error}")
        self.sock.settimeout(timeout)

    def close(self) -> None:
        try:
            self.packet("D")
        except Exception:
            pass
        self.sock.close()

    @staticmethod
    def _checksum(payload: str) -> int:
        return sum(payload.encode("ascii")) & 0xff

    def _recv_packet(self, timeout: float | None = None) -> str:
        old_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            data = bytearray()
            while True:
                chunk = self.sock.recv(1)
                if not chunk:
                    raise RuntimeError("GDB socket closed")
                if chunk == b"+":
                    continue
                if chunk == b"$":
                    break
            while True:
                chunk = self.sock.recv(1)
                if not chunk:
                    raise RuntimeError("GDB socket closed")
                if chunk == b"#":
                    self.sock.recv(2)
                    break
                data.extend(chunk)
            self.sock.sendall(b"+")
            return data.decode("ascii", "replace")
        finally:
            self.sock.settimeout(old_timeout)

    def packet(self, payload: str) -> str:
        self.sock.sendall(f"${payload}#{self._checksum(payload):02x}".encode("ascii"))
        return self._recv_packet()

    def continue_nowait(self) -> None:
        self.sock.sendall(b"$c#63")
        ack = self.sock.recv(1)
        if ack != b"+":
            raise RuntimeError(f"unexpected continue ACK: {ack!r}")

    def queue_continue(self) -> None:
        """Queue a continue packet without waiting for its ACK.

        A paused QMP state load may need its hold cleared before the GDB
        server can service the packet.  Call ``wait_for_continue_ack`` after
        releasing that hold.
        """
        self.sock.sendall(b"$c#63")

    def wait_for_continue_ack(self) -> None:
        ack = self.sock.recv(1)
        if ack != b"+":
            raise RuntimeError(f"unexpected continue ACK: {ack!r}")

    def step_nowait(self) -> None:
        self.sock.sendall(b"$s#73")
        ack = self.sock.recv(1)
        if ack != b"+":
            raise RuntimeError(f"unexpected step ACK: {ack!r}")

    def wait_for_stop(self, timeout: float) -> str:
        return self._recv_packet(timeout)

    def halt(self, timeout: float) -> str:
        readable, _, _ = select.select(
            [self.sock],
            [],
            [],
            min(timeout, 0.05),
        )
        if readable:
            return self._recv_packet(timeout)
        self.sock.sendall(b"\x03")
        return self._recv_packet(timeout)

    def insert_breakpoint(self, linear_address: int, kind: int = 1) -> None:
        response = self.packet(f"Z0,{linear_address:x},{kind:x}")
        if response != "OK":
            raise RuntimeError(
                "GDB software breakpoint insertion failed at "
                f"0x{linear_address:x}: {response!r}"
            )

    def remove_breakpoint(self, linear_address: int, kind: int = 1) -> None:
        response = self.packet(f"z0,{linear_address:x},{kind:x}")
        if response != "OK":
            raise RuntimeError(
                "GDB software breakpoint removal failed at "
                f"0x{linear_address:x}: {response!r}"
            )

    def registers(self) -> dict[str, int]:
        raw = self.packet("g")
        names = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
        ]
        return {
            name: struct.unpack("<I", bytes.fromhex(raw[idx * 8:(idx + 1) * 8]))[0]
            for idx, name in enumerate(names)
        }

    def write_register(self, name: str, value: int) -> None:
        names = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
        ]
        if name not in names:
            raise ValueError(f"unsupported register {name!r}")
        index = names.index(name)
        encoded = struct.pack("<I", value & 0xFFFFFFFF).hex()
        response = self.packet(f"P{index:x}={encoded}")
        if response != "OK":
            raise RuntimeError(f"GDB register write failed for {name}: {response!r}")

    def write_registers(self, registers: dict[str, int]) -> None:
        names = [
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
            "eip", "eflags", "cs", "ss", "ds", "es", "fs", "gs",
        ]
        current = self.registers()
        current.update({name: int(value) for name, value in registers.items() if name in names})
        if "eip" in registers:
            cs_base = (current["cs"] & 0xFFFF) << 4
            eip_linear = int(registers["eip"])
            eip_offset = eip_linear - cs_base
            if 0 <= eip_offset <= 0xFFFF:
                # DOSBox-X remotedebug reports real-mode EIP as a linear
                # address, but the full-register write packet accepts the
                # segment-relative IP value.
                current["eip"] = eip_offset
        encoded = "".join(struct.pack("<I", current[name] & 0xFFFFFFFF).hex() for name in names)
        response = self.packet(f"G{encoded}")
        if response != "OK":
            raise RuntimeError(f"GDB full register write failed: {response!r}")

    def call_near(self, offset: int, regs: dict[str, int]) -> dict[str, int]:
        cs = regs["cs"] & 0xFFFF
        ss = regs["ss"] & 0xFFFF
        sp = regs["esp"] & 0xFFFF
        eip_linear = regs["eip"]
        cs_base = cs << 4
        current_ip = eip_linear - cs_base
        if not 0 <= current_ip <= 0xFFFF:
            current_ip = eip_linear & 0xFFFF
        new_sp = (sp - 2) & 0xFFFF
        self.write_memory((ss << 4) + new_sp, struct.pack("<H", current_ip & 0xFFFF))
        updated = dict(regs)
        updated["esp"] = (regs["esp"] & 0xFFFF0000) | new_sp
        updated["eip"] = cs_base + (offset & 0xFFFF)
        self.write_registers(updated)
        return updated

    def write_memory(self, address: int, data: bytes) -> None:
        response = self.packet(f"M{address:x},{len(data):x}:{data.hex()}")
        if response != "OK":
            raise RuntimeError(f"GDB memory write failed at 0x{address:x}: {response!r}")

    def read_memory(self, address: int, size: int) -> bytes:
        if address < 0:
            raise ValueError("GDB memory read address must be non-negative")
        if size < 0:
            raise ValueError("GDB memory read size must be non-negative")
        if size == 0:
            return b""
        response = self.packet(f"m{address:x},{size:x}")
        if response.startswith("E"):
            raise RuntimeError(
                f"GDB memory read failed at 0x{address:x}: {response!r}"
            )
        try:
            data = bytes.fromhex(response)
        except ValueError as exc:
            raise RuntimeError(
                f"GDB memory read returned invalid hex at "
                f"0x{address:x}: {response!r}"
            ) from exc
        if len(data) != size:
            raise RuntimeError(
                f"GDB memory read at 0x{address:x} returned "
                f"{len(data)} bytes, expected {size}"
            )
        return data

    def read_memory_chunked(
        self,
        address: int,
        size: int,
        chunk_size: int = 4096,
    ) -> bytes:
        """Read a guest range in RSP-sized chunks.

        Some remotedebug backends can stop servicing QMP ``memdump`` while
        the guest is halted at a late breakpoint.  RSP remains available for
        the debugger in that state, so chunking keeps the fallback within the
        packet size accepted by older GDB stubs.
        """
        if chunk_size <= 0:
            raise ValueError("GDB memory read chunk size must be positive")
        return b"".join(
            self.read_memory(address + offset, min(chunk_size, size - offset))
            for offset in range(0, size, chunk_size)
        )

    def write_memory_chunked(self, address: int, data: bytes, chunk_size: int = 4096) -> None:
        for offset in range(0, len(data), chunk_size):
            self.write_memory(address + offset, data[offset : offset + chunk_size])


def pack_segment_offset(segment: int, offset: int) -> int:
    if not 0 <= segment <= 0xFFFF:
        raise ValueError(f"breakpoint segment is outside 16-bit range: {segment}")
    if not 0 <= offset <= 0xFFFF:
        raise ValueError(f"breakpoint offset is outside 16-bit range: {offset}")
    return (segment << 16) | offset


def parse_dos_integer(spec: str) -> int:
    """Parse debugger address components in decimal or DOS-style hex.

    The command-line contract historically accepted bare four-digit real-mode
    components such as ``0824:03d1``.  Python's ``int(value, 0)`` rejects a
    leading-zero decimal token, so retain that established spelling while
    keeping explicit ``0x`` and ordinary decimal input unchanged.
    """
    try:
        return int(spec, 0)
    except ValueError:
        if spec and all(
            character in "0123456789abcdefABCDEF" for character in spec
        ):
            return int(spec, 16)
        raise


def parse_segmented_nth_breakpoint_action(
    action: str,
) -> tuple[int, int]:
    parts = action.split(":")
    if len(parts) != 4 or parts[0] != "breaksonth":
        raise ValueError(
            "breaksonth action syntax: "
            "breaksonth:<segment>:<offset>:<positive-hit-count>"
        )
    segment = parse_dos_integer(parts[1])
    offset = parse_dos_integer(parts[2])
    hit_count = parse_dos_integer(parts[3])
    if hit_count < 1:
        raise ValueError("breakpoint hit count must be positive")
    return pack_segment_offset(segment, offset), hit_count


def parse_segmented_breakpoint_series_action(
    action: str,
) -> tuple[int, int, list[int]]:
    parts = action.split(":")
    if len(parts) != 4 or parts[0] != "breakseries":
        raise ValueError(
            "breakseries action syntax: "
            "breakseries:<segment>:<offset>:<hit>+<hit>[+<hit>...]"
        )
    segment = parse_dos_integer(parts[1])
    offset = parse_dos_integer(parts[2])
    pack_segment_offset(segment, offset)
    hits = parse_breakpoint_hit_series(parts[3].replace("+", ","))
    return segment, offset, hits


def install_running_breakpoint(
    gdb: RspClient, linear_address: int, timeout: float
) -> str:
    stop = gdb.halt(timeout)
    gdb.insert_breakpoint(linear_address)
    gdb.continue_nowait()
    return stop


def clear_halted_breakpoint(
    gdb: RspClient, linear_address: int, timeout: float
) -> str:
    gdb.remove_breakpoint(linear_address)
    gdb.step_nowait()
    return gdb.wait_for_stop(timeout)


def step_past_optional_halted_breakpoint(
    gdb: RspClient, linear_address: int, timeout: float
) -> str:
    """Step once whether the completed state matcher retained its breakpoint."""
    try:
        gdb.remove_breakpoint(linear_address)
    except RuntimeError as error:
        if "E01" not in str(error):
            raise
    gdb.step_nowait()
    return gdb.wait_for_stop(timeout)


def prepare_full_state_resume_breakpoint(
    gdb: RspClient,
    linear_address: int,
    timeout: float,
    registers: dict[str, int],
) -> dict[str, int]:
    """Advance a full-state restore parked on its checkpoint instruction.

    DOSBox-X save states taken at a halted state breakpoint can restore with
    EIP still equal to that breakpoint.  A subsequent state matcher must
    execute the instruction once before inserting the same breakpoint, or it
    will repeatedly observe the restored value.  States already past the
    address are left untouched.
    """
    if registers.get("eip") == linear_address:
        step_past_optional_halted_breakpoint(gdb, linear_address, timeout)
        return gdb.registers()
    return registers


def should_defer_paused_load_release(
    *,
    paused: bool,
    continue_after_load: bool,
    has_edits: bool,
    has_resume_checkpoint: bool,
) -> bool:
    """Keep QMP's load hold through exact edits or resume setup."""
    return paused and (
        (continue_after_load and has_edits) or has_resume_checkpoint
    )


def remove_halted_breakpoint(
    gdb: RspClient, linear_address: int
) -> None:
    gdb.remove_breakpoint(linear_address)


def remove_halted_segmented_breakpoint(
    gdb: RspClient,
    segment: int,
    offset: int,
) -> int:
    backend_address = pack_segment_offset(segment, offset)
    remove_halted_breakpoint(gdb, backend_address)
    return backend_address


def install_halted_breakpoint(
    gdb: RspClient, linear_address: int
) -> None:
    gdb.insert_breakpoint(linear_address)
    gdb.continue_nowait()


def stop_on_halted_breakpoint(
    gdb: RspClient, linear_address: int, timeout: float
) -> str:
    install_halted_breakpoint(gdb, linear_address)
    return gdb.wait_for_stop(timeout)


def stop_on_halted_segmented_breakpoint(
    gdb: RspClient,
    segment: int,
    offset: int,
    timeout: float,
) -> tuple[str, dict[str, int]]:
    backend_address = pack_segment_offset(segment, offset)
    stop = stop_on_halted_breakpoint(
        gdb,
        backend_address,
        timeout,
    )
    registers = gdb.registers()
    expected_eip = (segment << 4) + offset
    actual_eip = registers["eip"]
    if actual_eip != expected_eip:
        raise RuntimeError(
            "segmented breakpoint stopped at the wrong instruction: "
            f"expected {segment:04x}:{offset:04x} "
            f"(linear 0x{expected_eip:05x}), "
            f"observed EIP 0x{actual_eip:05x}"
        )
    return stop, registers


def stop_on_nth_breakpoint(
    gdb: RspClient,
    linear_address: int,
    hit_count: int,
    timeout: float,
) -> str:
    if hit_count < 1:
        raise ValueError("breakpoint hit count must be positive")
    gdb.halt(timeout)
    gdb.insert_breakpoint(linear_address)
    stop = ""
    for hit_index in range(hit_count):
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        if hit_index + 1 < hit_count:
            gdb.remove_breakpoint(linear_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(linear_address)
    return stop


def stop_on_post_resume_nth_breakpoint(
    gdb: RspClient,
    linear_address: int,
    hit_count: int,
    timeout: float,
) -> tuple[str, dict[str, int]]:
    return stop_on_post_resume_nth_breakpoint_at_backend_address(
        gdb,
        linear_address,
        linear_address,
        hit_count,
        timeout,
    )


def stop_on_post_resume_nth_breakpoint_at_backend_address(
    gdb: RspClient,
    backend_address: int,
    expected_eip: int,
    hit_count: int,
    timeout: float,
) -> tuple[str, dict[str, int]]:
    if hit_count < 1:
        raise ValueError("breakpoint hit count must be positive")
    gdb.insert_breakpoint(backend_address)
    stop = ""
    for hit_index in range(hit_count):
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        if hit_index + 1 < hit_count:
            gdb.remove_breakpoint(backend_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(backend_address)
    registers = gdb.registers()
    state_stop_hook = os.environ.get("DOS_RE_HARNESS_STATE_INPUT_HOOK_LINEAR")
    state_stop_value = os.environ.get("DOS_RE_HARNESS_STATE_INPUT_STOP_VALUE")
    state_stop_eip = (
        int(state_stop_hook, 0)
        if state_stop_hook is not None and state_stop_value is not None
        else None
    )
    if registers["eip"] != expected_eip and registers["eip"] != state_stop_eip:
        raise RuntimeError(
            "post-resume breakpoint stopped at the wrong instruction: "
            f"expected 0x{expected_eip:05x}, "
            f"observed EIP 0x{registers['eip']:05x}"
        )
    return stop, registers


def stop_on_post_resume_nth_segmented_breakpoint(
    gdb: RspClient,
    segment: int,
    offset: int,
    hit_count: int,
    timeout: float,
) -> tuple[str, dict[str, int]]:
    return stop_on_post_resume_nth_breakpoint_at_backend_address(
        gdb,
        pack_segment_offset(segment, offset),
        (segment << 4) + offset,
        hit_count,
        timeout,
    )


def parse_breakpoint_hit_series(spec: str) -> list[int]:
    if not spec:
        raise ValueError("breakpoint hit series must not be empty")
    parts = spec.split(",")
    if any(not part.strip() for part in parts):
        raise ValueError(
            "breakpoint hit series must be comma-separated positive integers"
        )
    hits = [int(part, 0) for part in parts]
    if any(hit < 1 for hit in hits):
        raise ValueError("breakpoint hit series values must be positive")
    if any(left >= right for left, right in zip(hits, hits[1:])):
        raise ValueError(
            "breakpoint hit series values must be strictly increasing"
        )
    return hits


def parse_memory_region(spec: str) -> tuple[int, int]:
    parts = spec.rsplit(":", 1)
    if len(parts) != 2:
        raise ValueError("memory region syntax: <linear-address>:<positive-size>")
    address = int(parts[0], 0)
    size = int(parts[1], 0)
    if address < 0:
        raise ValueError("memory region address must be non-negative")
    if size < 1:
        raise ValueError("memory region size must be positive")
    return address, size


def should_clear_resume_checkpoint_breakpoint(
    resume_linear: int,
    post_resume_break_linear: int | None,
    post_resume_break_segmented: tuple[int, int] | None,
    observed_value_count: int,
) -> bool:
    """Return whether a halted state breakpoint must be stepped past first."""
    if observed_value_count > 1:
        return True
    if post_resume_break_segmented is not None:
        segment, offset = post_resume_break_segmented
        target_linear = (segment << 4) + offset
    else:
        target_linear = post_resume_break_linear
    return target_linear is not None and target_linear != resume_linear


def stop_on_post_resume_breakpoint_series(
    gdb: RspClient,
    linear_address: int,
    hit_counts: list[int],
    timeout: float,
    capture_hit: Callable[[int, str, dict[str, int]], None],
) -> tuple[str, dict[str, int]]:
    return stop_on_post_resume_breakpoint_series_at_backend_address(
        gdb,
        linear_address,
        linear_address,
        hit_counts,
        timeout,
        capture_hit,
    )


def stop_on_post_resume_breakpoint_series_at_backend_address(
    gdb: RspClient,
    backend_address: int,
    expected_eip: int,
    hit_counts: list[int],
    timeout: float,
    capture_hit: Callable[[int, str, dict[str, int]], None],
) -> tuple[str, dict[str, int]]:
    if not hit_counts:
        raise ValueError("breakpoint hit series must not be empty")
    if any(hit < 1 for hit in hit_counts):
        raise ValueError("breakpoint hit series values must be positive")
    if any(left >= right for left, right in zip(hit_counts, hit_counts[1:])):
        raise ValueError(
            "breakpoint hit series values must be strictly increasing"
        )
    requested = set(hit_counts)
    final_hit = hit_counts[-1]
    final_stop = ""
    final_registers: dict[str, int] | None = None
    gdb.insert_breakpoint(backend_address)
    for hit_index in range(1, final_hit + 1):
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        if hit_index in requested:
            registers = gdb.registers()
            if registers["eip"] != expected_eip:
                raise RuntimeError(
                    "post-resume breakpoint series stopped at the wrong "
                    f"instruction on hit {hit_index}: "
                    f"expected 0x{expected_eip:05x}, "
                    f"observed EIP 0x{registers['eip']:05x}"
                )
            capture_hit(hit_index, stop, registers)
            final_stop = stop
            final_registers = registers
        if hit_index < final_hit:
            gdb.remove_breakpoint(backend_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(backend_address)
    if final_registers is None:
        raise RuntimeError("breakpoint series did not capture its final hit")
    return final_stop, final_registers


def stop_on_post_resume_segmented_breakpoint_series(
    gdb: RspClient,
    segment: int,
    offset: int,
    hit_counts: list[int],
    timeout: float,
    capture_hit: Callable[[int, str, dict[str, int]], None],
) -> tuple[str, dict[str, int]]:
    return stop_on_post_resume_breakpoint_series_at_backend_address(
        gdb,
        pack_segment_offset(segment, offset),
        (segment << 4) + offset,
        hit_counts,
        timeout,
        capture_hit,
    )


def parse_segmented_address(spec: str) -> tuple[int, int]:
    parts = spec.split(":")
    if len(parts) != 2:
        raise ValueError(
            "segmented address syntax: <segment>:<offset>"
        )
    segment = parse_dos_integer(parts[0])
    offset = parse_dos_integer(parts[1])
    if not 0 <= segment <= 0xFFFF:
        raise ValueError("breakpoint segment is outside 16-bit range")
    if not 0 <= offset <= 0xFFFF:
        raise ValueError("breakpoint offset is outside 16-bit range")
    return segment, offset


def stop_on_state_breakpoint(
    gdb: RspClient,
    linear_address: int,
    predicate: tuple[str, str, int],
    max_hits: int,
    timeout: float,
    read_state: Callable[[dict[str, int]], dict[str, int]],
) -> tuple[str, dict[str, int], dict[str, int], int]:
    if max_hits < 1:
        raise ValueError("state breakpoint maximum hit count must be positive")
    gdb.halt(timeout)
    gdb.insert_breakpoint(linear_address)
    for hit_index in range(1, max_hits + 1):
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        registers = gdb.registers()
        state = read_state(registers)
        if not evaluate_state_predicates(state, [predicate]):
            return stop, registers, state, hit_index
        if hit_index < max_hits:
            gdb.remove_breakpoint(linear_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(linear_address)
    raise TimeoutError(
        "state breakpoint predicate "
        f"{format_state_predicates([predicate])} was not met within "
        f"{max_hits} hits at 0x{linear_address:05x}"
    )


def apply_running_poke(
    gdb: RspClient, linear_address: int, data: bytes, timeout: float
) -> str:
    stop = gdb.halt(timeout)
    gdb.write_memory(linear_address, data)
    gdb.continue_nowait()
    return stop


def apply_halted_poke(
    gdb: RspClient, linear_address: int, data: bytes
) -> None:
    gdb.write_memory(linear_address, data)
    gdb.continue_nowait()


def parse_screen_wait_action(
    action: str,
    operation: str,
) -> tuple[str, float, float]:
    parts = action.split(":")
    if len(parts) not in {3, 4} or parts[0] != operation:
        raise ValueError(
            f"{operation} syntax: "
            f"{operation}:<state>:<timeout>[:<poll-interval>], "
            f"got {action!r}"
        )
    timeout = float(parts[2])
    poll_interval = float(parts[3]) if len(parts) == 4 else 0.5
    if timeout <= 0:
        raise ValueError(f"{operation} timeout must be positive")
    if poll_interval <= 0:
        raise ValueError(f"{operation} poll interval must be positive")
    return parts[1], timeout, poll_interval


def parse_run_for_action(action: str) -> float:
    parts = action.split(":")
    if len(parts) != 2 or parts[0] != "runfor":
        raise ValueError(
            f"runfor action syntax: runfor:<positive-seconds>, got {action!r}"
        )
    seconds = float(parts[1])
    if seconds <= 0:
        raise ValueError("runfor duration must be positive")
    return seconds


def parse_run_tap_action(action: str) -> tuple[str, float]:
    parts = action.split(":")
    if len(parts) not in {2, 3} or parts[0] != "runtap":
        raise ValueError(
            "runtap action syntax: runtap:<qcode>[:<positive-seconds>], "
            f"got {action!r}"
        )
    qcode = parts[1]
    if not qcode or not all(
        character.isalnum() or character in {"_", "-"}
        for character in qcode
    ):
        raise ValueError("runtap qcode is invalid")
    seconds = float(parts[2]) if len(parts) == 3 else 0.2
    if seconds <= 0:
        raise ValueError("runtap hold duration must be positive")
    return qcode, seconds


def parse_run_until_stop_action(action: str) -> float:
    parts = action.split(":")
    if len(parts) != 2 or parts[0] != "rununtilstop":
        raise ValueError(
            "rununtilstop action syntax: "
            f"rununtilstop:<positive-timeout-seconds>, got {action!r}"
        )
    timeout = float(parts[1])
    if timeout <= 0:
        raise ValueError("rununtilstop timeout must be positive")
    return timeout


def wait_for_qmp_screen(
    qmp: Any,
    classifier: Any,
    address: int,
    size: int,
    expected_state: str,
    timeout: float,
    poll_interval: float,
) -> bytes:
    deadline = time.monotonic() + timeout
    last_state = "unknown"
    while time.monotonic() < deadline:
        raw = qmp.memdump(address, size)
        last_state = classifier.classify(raw)
        if last_state == expected_state:
            return raw
        if poll_interval > 0:
            time.sleep(poll_interval)
    raise TimeoutError(
        "timed out waiting for save-state load readiness screen "
        f"{expected_state!r}; last={last_state!r}"
    )


class QmpClient:
    _memory_fallback: Callable[[int, int], bytes] | None = None

    @classmethod
    def set_memory_fallback(
        cls,
        reader: Callable[[int, int], bytes] | None,
    ) -> None:
        cls._memory_fallback = reader

    def __init__(self, host: str, port: int, timeout: float) -> None:
        deadline = time.time() + timeout
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                self.sock = socket.create_connection((host, port), 1.0)
                break
            except OSError as exc:
                last_error = exc
                time.sleep(0.1)
        else:
            raise RuntimeError(f"QMP port {port} did not open: {last_error}")
        self.sock.settimeout(timeout)
        self._recv_json()
        self.command("qmp_capabilities")
        self.supports_immediate_savestate = False
        self.supports_loadstate_paused = False
        try:
            commands = self.command("query-commands").get("return", [])
            names = {
                item.get("name")
                for item in commands
                if isinstance(item, dict)
            }
            self.supports_immediate_savestate = "savestate-immediate" in names
            self.supports_loadstate_paused = "loadstate-paused" in names
        except RuntimeError:
            # Older backends remain usable through the queued request path.
            self.supports_immediate_savestate = False

    def close(self) -> None:
        self.sock.close()

    def _recv_json(self) -> dict[str, Any]:
        data = bytearray()
        while True:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("QMP socket closed")
            data.extend(chunk)
            try:
                return json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                continue

    def command(
        self,
        execute: str,
        arguments: dict[str, Any] | None = None,
        timeout: float | None = None,
        sent_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        msg: dict[str, Any] = {"execute": execute}
        if arguments is not None:
            msg["arguments"] = arguments
        previous_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        try:
            self.sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            if sent_event is not None:
                sent_event.set()
            response = self._recv_json()
        finally:
            if timeout is not None:
                self.sock.settimeout(previous_timeout)
        if "error" in response:
            raise RuntimeError(f"QMP {execute} failed: {response}")
        return response

    def key_tap(self, qcode: str, hold_seconds: float = 0.15) -> None:
        self.command(
            "send-key",
            {
                "keys": [{"type": "qcode", "data": qcode}],
                "hold-time": int(hold_seconds * 1000),
            },
        )

    def key_event(self, qcode: str, down: bool) -> None:
        self.command(
            "input-send-event",
            {
                "events": [
                    {
                        "type": "key",
                        "data": {
                            "down": down,
                            "key": {"type": "qcode", "data": qcode},
                        },
                    }
                ]
            },
        )

    def key_hold(self, qcode: str, hold_seconds: float) -> None:
        self.key_event(qcode, True)
        time.sleep(hold_seconds)
        self.key_event(qcode, False)

    def key_chord(self, qcodes: list[str], hold_seconds: float = 0.15) -> None:
        if len(qcodes) < 2:
            raise ValueError("key chord requires at least two qcodes")
        for qcode in qcodes:
            self.key_event(qcode, True)
        time.sleep(hold_seconds)
        for qcode in reversed(qcodes):
            self.key_event(qcode, False)

    def capture_wave(self, start: bool) -> None:
        self.command("capture-wave-start" if start else "capture-wave-stop")

    def memdump(self, address: int, size: int) -> bytes:
        try:
            response = self.command(
                "memdump",
                {"address": address, "size": size},
            )
        except TimeoutError:
            fallback = type(self)._memory_fallback
            if fallback is None:
                raise
            data = fallback(address, size)
            if len(data) != size:
                raise RuntimeError(
                    "RSP memory fallback returned an unexpected size: "
                    f"{len(data)} (expected {size})"
                )
            return data
        payload = response.get("return", {}).get("data")
        if not isinstance(payload, str):
            raise RuntimeError(f"QMP memdump did not return base64 data: {response}")
        return base64.b64decode(payload)

    def memdump_chunked(
        self,
        address: int,
        size: int,
        chunk_size: int = 4096,
    ) -> bytes:
        """Read a guest range as bounded QMP requests.

        Older DOSBox-X remotedebug builds can stop servicing a large QMP
        ``memdump`` late in a run even though small requests still complete.
        Keeping the request size bounded also makes the RSP fallback useful:
        a timeout is isolated to one chunk instead of invalidating the whole
        checkpoint range.
        """
        if chunk_size <= 0:
            raise ValueError("QMP memory read chunk size must be positive")
        return b"".join(
            self.memdump(
                address + offset,
                min(chunk_size, size - offset),
            )
            for offset in range(0, size, chunk_size)
        )

    def dacdump(self) -> dict[str, Any]:
        response = self.command("dacdump")
        result = response.get("return")
        if not isinstance(result, dict):
            raise RuntimeError(f"QMP dacdump did not return an object: {response}")
        payload = result.get("data")
        if not isinstance(payload, str):
            raise RuntimeError(f"QMP dacdump did not return base64 data: {response}")
        data = base64.b64decode(payload)
        if len(data) != 256 * 3:
            raise RuntimeError(
                "QMP dacdump returned an unexpected palette size: "
                f"{len(data)}"
            )
        return {
            "data": data,
            "bits": int(result.get("bits", 0)),
            "pel_mask": int(result.get("pel_mask", 0)),
            "pel_index": int(result.get("pel_index", 0)),
            "state": int(result.get("state", 0)),
            "write_index": int(result.get("write_index", 0)),
            "read_index": int(result.get("read_index", 0)),
            "first_changed": int(result.get("first_changed", 0)),
        }

    @staticmethod
    def _decode_display_frame(
        result: object,
        command_name: str,
    ) -> dict[str, Any]:
        if not isinstance(result, dict):
            raise RuntimeError(
                f"QMP {command_name} did not return a frame object: {result}"
            )
        payload = result.get("data")
        if not isinstance(payload, str):
            raise RuntimeError(
                f"QMP {command_name} did not return base64 data: {result}"
            )
        data = base64.b64decode(payload)
        encoding = result.get("encoding", "raw")
        if encoding == "zlib":
            try:
                data = zlib.decompress(data)
            except zlib.error as error:
                raise RuntimeError(
                    f"QMP {command_name} returned invalid zlib data"
                ) from error
        elif encoding != "raw":
            raise RuntimeError(
                f"QMP {command_name} returned unsupported encoding: "
                f"{encoding}"
            )
        width = int(result.get("width", 0))
        height = int(result.get("height", 0))
        bpp = int(result.get("bpp", 0))
        pitch = int(result.get("pitch", 0))
        if width <= 0 or height <= 0 or bpp <= 0 or pitch <= 0:
            raise RuntimeError(
                f"QMP {command_name} returned invalid frame geometry: "
                f"{width}x{height} bpp={bpp} pitch={pitch}"
            )
        expected_size = pitch * height
        declared_size = int(result.get("size", -1))
        if len(data) != expected_size or declared_size != expected_size:
            raise RuntimeError(
                f"QMP {command_name} returned an unexpected frame size: "
                f"decoded={len(data)} declared={declared_size} "
                f"expected={expected_size}"
            )
        palette_payload = result.get("palette")
        palette = None
        if palette_payload is not None:
            if not isinstance(palette_payload, str):
                raise RuntimeError(
                    f"QMP {command_name} returned invalid palette data"
                )
            palette = base64.b64decode(palette_payload)
            declared_palette_size = int(result.get("palette_size", -1))
            if len(palette) != 256 * 3 or declared_palette_size != len(palette):
                raise RuntimeError(
                    f"QMP {command_name} returned an unexpected palette size: "
                    f"decoded={len(palette)} declared={declared_palette_size}"
                )
        return {
            "data": data,
            "palette": palette,
            "width": width,
            "height": height,
            "bpp": bpp,
            "pitch": pitch,
            "generation": int(result.get("generation", 0)),
        }

    def displaydump(self) -> dict[str, Any]:
        """Return the backend's last completed logical source frame.

        Unlike ``screendump``, this does not ask the running renderer to
        produce a new host screenshot.  It is therefore safe to use while the
        guest CPU is halted at an exact debugger boundary.
        """
        response = self.command("displaydump")
        return self._decode_display_frame(
            response.get("return"),
            "displaydump",
        )

    def start_display_history(self, capacity: int) -> dict[str, int]:
        """Arm bounded completed-frame retention before guest continuation."""
        if capacity <= 0:
            raise ValueError("display history capacity must be positive")
        response = self.command(
            "displayhistory-start",
            {"capacity": capacity},
        )
        result = response.get("return")
        if not isinstance(result, dict):
            raise RuntimeError(
                "QMP displayhistory-start did not return an object: "
                f"{response}"
            )
        return {
            "capacity": int(result.get("capacity", 0)),
            "generation": int(result.get("generation", 0)),
        }

    def stop_display_history(self) -> dict[str, Any]:
        """Stop retention and return every retained completed source frame."""
        response = self.command("displayhistory-stop")
        result = response.get("return")
        if not isinstance(result, dict):
            raise RuntimeError(
                "QMP displayhistory-stop did not return an object: "
                f"{response}"
            )
        encoded_frames = result.get("frames")
        if not isinstance(encoded_frames, list):
            raise RuntimeError(
                "QMP displayhistory-stop did not return a frame list: "
                f"{response}"
            )
        frames = [
            self._decode_display_frame(frame, "displayhistory-stop")
            for frame in encoded_frames
        ]
        return {
            "capacity": int(result.get("capacity", 0)),
            "dropped": int(result.get("dropped", 0)),
            "frames": frames,
        }

    def screendump(self) -> bytes:
        response = self.command("screendump")
        payload = response.get("return", {}).get("data")
        if not isinstance(payload, str):
            raise RuntimeError(f"QMP screendump did not return base64 data: {response}")
        data = base64.b64decode(payload)
        if not data:
            raise RuntimeError(f"QMP screendump returned an empty payload: {response}")
        return data

    def save_state(
        self,
        path: Path,
        request_sent: threading.Event | None = None,
    ) -> Path:
        response = self.command(
            "savestate",
            {"file": str(path)},
            timeout=35.0,
            sent_event=request_sent,
        )
        returned = response.get("return", {}).get("file")
        if returned != str(path):
            raise RuntimeError(
                "QMP savestate returned an unexpected path: "
                f"{response}"
            )
        return path

    def save_state_immediate(self, path: Path) -> Path:
        """Save without resuming the emulated CPU.

        This is supported by the pinned remote-debug DOSBox-X backend for
        halted-boundary capture.  It is deliberately separate from the
        queued ``savestate`` request, whose servicing requires the emulator
        main loop to run.
        """
        response = self.command(
            "savestate-immediate",
            {"file": str(path)},
            timeout=35.0,
        )
        returned = response.get("return", {}).get("file")
        if returned != str(path):
            raise RuntimeError(
                "QMP immediate savestate returned an unexpected path: "
                f"{response}"
            )
        return path

    def load_state(self, path: Path) -> Path:
        response = self.command(
            "loadstate",
            {"file": str(path)},
            timeout=35.0,
        )
        returned = response.get("return", {}).get("file")
        if returned != str(path):
            raise RuntimeError(
                "QMP loadstate returned an unexpected path: "
                f"{response}"
            )
        return path

    def load_state_paused(self, path: Path) -> Path:
        """Load on the emulation thread and pause before guest execution."""
        response = self.command(
            "loadstate-paused",
            {"file": str(path)},
            timeout=35.0,
        )
        returned = response.get("return", {}).get("file")
        if returned != str(path):
            raise RuntimeError(
                "QMP paused loadstate returned an unexpected path: "
                f"{response}"
            )
        return path


def capture_optional_screenshot(
    qmp: Any,
    path: Path,
) -> str | None:
    last_error: str | None = None
    for attempt in range(3):
        try:
            data = qmp.screendump()
        except RuntimeError as exc:
            last_error = str(exc)
            continue
        # A running DOSBox-X can return a short PNG while the display page is
        # being replaced. Do not retain a nominally successful truncated file;
        # retry the same sample so sequence manifests never advertise corrupt
        # screenshots as evidence.
        if _is_complete_png(data):
            path.write_bytes(data)
            return None
        last_error = (
            "QMP screendump returned a truncated PNG "
            f"({len(data)} bytes)"
        )
        if attempt < 2:
            time.sleep(0.01)
    return last_error or "QMP screendump returned no data"


def capture_targeted_sequence_screenshot(
    qmp: Any,
    path: Path,
    capture_root: Path,
) -> tuple[str | None, bool]:
    """Capture one running sequence frame, recovering a backend root PNG."""
    before_screens = set(capture_root.glob("*.png"))
    error = capture_optional_screenshot(qmp, path)
    if error is None:
        return None, False
    side_effects = sorted(
        (
            candidate
            for candidate in capture_root.glob("*.png")
            if candidate not in before_screens
        ),
        key=lambda candidate: candidate.stat().st_mtime_ns,
        reverse=True,
    )
    for side_effect in side_effects:
        data = _read_stable_nonempty_file(side_effect, 1.0)
        if data is not None and _is_complete_png(data):
            path.write_bytes(data)
            return None, True
    return error, False


def _is_complete_png(data: bytes) -> bool:
    return (
        len(data) >= 24
        and data.startswith(b"\x89PNG\r\n\x1a\n")
        and b"IEND" in data[-32:]
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_save_state_checkpoint_metadata(
    save_state_path: Path,
) -> dict[str, Any]:
    metadata_path = save_state_path.with_name(
        "remote_runtime_registers.json"
    )
    if not metadata_path.is_file():
        raise ValueError(
            "full emulator state requires companion checkpoint metadata: "
            f"{metadata_path}"
        )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    expected_sha256 = metadata.get("save_state_sha256")
    actual_sha256 = sha256_file(save_state_path)
    if expected_sha256 != actual_sha256:
        raise ValueError(
            "full emulator state does not match companion metadata: "
            f"expected SHA-256 {expected_sha256!r}, observed "
            f"{actual_sha256}"
        )
    dump_segment_value = metadata.get("dump_segment_value")
    if not isinstance(dump_segment_value, int):
        raise ValueError(
            "full emulator state companion metadata lacks "
            "dump_segment_value"
        )
    return metadata


def finalize_halted_checkpoint_save_state(
    qmp: Any,
    gdb: Any,
    breakpoint_linear: int,
    checkpoint_record: dict[str, Any],
    timeout: float,
    read_post_save_state: (
        Callable[[dict[str, int]], dict[str, int]] | None
    ) = None,
) -> tuple[str, dict[str, int]]:
    checkpoint_metadata = json.loads(
        (
            Path(checkpoint_record["path"])
            / "remote_runtime_registers.json"
        ).read_text(encoding="utf-8")
    )
    checkpoint_stop = checkpoint_record.get("stop")
    if checkpoint_stop is None:
        checkpoint_stop = checkpoint_metadata["stop"]
    checkpoint_registers = checkpoint_record.get("registers")
    if checkpoint_registers is None:
        checkpoint_registers = checkpoint_metadata["registers"]
    return save_halted_checkpoint_state(
        qmp,
        gdb,
        checkpoint_record,
        checkpoint_stop,
        checkpoint_registers,
        timeout,
        breakpoint_linear,
        read_post_save_state,
    )


def save_halted_checkpoint_state(
    qmp: Any,
    gdb: Any,
    checkpoint_record: dict[str, Any],
    stop: str,
    registers: dict[str, int],
    timeout: float,
    breakpoint_linear: int | None = None,
    read_post_save_state: (
        Callable[[dict[str, int]], dict[str, int]] | None
    ) = None,
) -> tuple[str, dict[str, int]]:
    """Save a full emulator state at a halted boundary.

    This is useful when a memory transplant has established a proven state
    immediately before an event.  Pinned remote-debug DOSBox-X backends can
    serialize an explicitly halted machine directly; older backends fall back
    to removing the optional breakpoint and using one debugger step so the
    main-loop savestate request can be serviced.
    """
    checkpoint_path = Path(checkpoint_record["path"])
    save_state_path = checkpoint_path / "remote_runtime.sav"
    metadata_path = checkpoint_path / "remote_runtime_registers.json"
    immediate_save = (
        getattr(qmp, "save_state_immediate", None)
        if getattr(qmp, "supports_immediate_savestate", False)
        else None
    )
    if immediate_save is not None:
        # The backend serializes the halted machine directly from the QMP
        # thread.  No breakpoint removal, guest step, or resume is needed.
        immediate_save(save_state_path)
        final_stop = stop
        final_registers = registers
        step_stop = None
    elif breakpoint_linear is not None:
        gdb.remove_breakpoint(breakpoint_linear)
        gdb.step_nowait()
        step_stop = gdb.wait_for_stop(timeout)
    else:
        step_stop = None
    worker: threading.Thread | None = None

    request_sent = threading.Event()
    save_error: list[BaseException] = []

    def save_worker() -> None:
        try:
            qmp.save_state(save_state_path, request_sent)
        except BaseException as exc:
            save_error.append(exc)
            request_sent.set()

    if immediate_save is None:
        worker = threading.Thread(
            target=save_worker,
            name="dos-re-first-boundary-savestate",
            daemon=True,
        )
        worker.start()
        if not request_sent.wait(timeout):
            raise TimeoutError("QMP halted savestate request was not sent")
        if save_error:
            raise RuntimeError("QMP halted savestate request failed") from save_error[0]
        gdb.continue_nowait()
        worker.join(40.0)
        final_stop = gdb.halt(timeout)
        final_registers = gdb.registers()
    if worker is not None and worker.is_alive():
        raise TimeoutError("QMP halted savestate did not complete within 40 seconds")
    if save_error:
        raise RuntimeError("QMP halted savestate failed") from save_error[0]
    if not save_state_path.is_file():
        raise RuntimeError(
            "QMP halted savestate reported success but did not create "
            f"{save_state_path}"
        )
    save_state_size = save_state_path.stat().st_size
    if save_state_size == 0:
        raise RuntimeError(
            f"QMP halted savestate created an empty file: {save_state_path}"
        )
    save_state_sha256 = sha256_file(save_state_path)
    post_save_state = (
        read_post_save_state(final_registers)
        if read_post_save_state is not None
        else None
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "save_state": str(save_state_path),
            "save_state_size": save_state_size,
            "save_state_sha256": save_state_sha256,
            "save_state_resume": {
                "breakpoint_linear": None,
                "single_step_stop": None,
                "post_save_stop": final_stop,
                "post_save_registers": final_registers,
                "post_save_state": post_save_state,
                "halted_boundary": True,
                "pre_save_stop": stop,
                "pre_save_registers": registers,
                "step_stop": step_stop,
                "immediate_halted": immediate_save is not None,
            },
        }
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checkpoint_record.update(
        {
            "save_state": str(save_state_path),
            "save_state_size": save_state_size,
            "save_state_sha256": save_state_sha256,
            "save_state_resume": metadata["save_state_resume"],
        }
    )
    return final_stop, final_registers


def finalize_halted_state_input_save_state(
    qmp: Any,
    gdb: Any,
    checkpoint_record: dict[str, Any],
    stop: str,
    registers: dict[str, int],
    timeout: float,
    read_post_save_state: (
        Callable[[dict[str, int]], dict[str, int]] | None
    ) = None,
) -> tuple[str, dict[str, int]]:
    """Save a state after a backend-requested state-input stop.

    Pinned backends serialize the halted machine immediately, preserving the
    exact state-stop boundary. Older backends fall back to stepping away from
    the hook and using the queued QMP save handshake.
    """
    checkpoint_path = Path(checkpoint_record["path"])
    save_state_path = checkpoint_path / "remote_runtime.sav"
    metadata_path = checkpoint_path / "remote_runtime_registers.json"

    immediate_save = (
        getattr(qmp, "save_state_immediate", None)
        if getattr(qmp, "supports_immediate_savestate", False)
        else None
    )
    if immediate_save is not None:
        immediate_save(save_state_path)
        final_stop = stop
        final_registers = registers
        step_stop = None
        breakpoint_linear = None
        worker = None
        save_error: list[BaseException] = []
    else:
        gdb.step_nowait()
        step_stop = gdb.wait_for_stop(timeout)
        step_registers = gdb.registers()
        breakpoint_linear = step_registers["eip"] & 0xFFFFFFFF
        gdb.insert_breakpoint(breakpoint_linear)

        request_sent = threading.Event()
        save_error = []

        def save_worker() -> None:
            try:
                qmp.save_state(save_state_path, request_sent)
            except BaseException as exc:
                save_error.append(exc)
                request_sent.set()

        worker = threading.Thread(
            target=save_worker,
            name="dos-re-state-input-savestate",
            daemon=True,
        )
        worker.start()
        if not request_sent.wait(timeout):
            gdb.remove_breakpoint(breakpoint_linear)
            raise TimeoutError("QMP state-input savestate request was not sent")
        if save_error:
            gdb.remove_breakpoint(breakpoint_linear)
            raise RuntimeError(
                "QMP state-input savestate request failed"
            ) from save_error[0]

        gdb.continue_nowait()
        final_stop = gdb.wait_for_stop(timeout)
        worker.join(40.0)
        gdb.remove_breakpoint(breakpoint_linear)
        final_registers = gdb.registers()
    post_save_state = (
        read_post_save_state(final_registers)
        if read_post_save_state is not None
        else None
    )
    if worker is not None and worker.is_alive():
        raise TimeoutError(
            "QMP state-input savestate did not complete within 40 seconds"
        )
    if save_error:
        raise RuntimeError("QMP state-input savestate failed") from save_error[0]
    if not save_state_path.is_file():
        raise RuntimeError(
            "QMP state-input savestate reported success but did not create "
            f"{save_state_path}"
        )
    save_state_size = save_state_path.stat().st_size
    if save_state_size == 0:
        raise RuntimeError(
            f"QMP state-input savestate created an empty file: {save_state_path}"
        )
    save_state_sha256 = sha256_file(save_state_path)

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "save_state": str(save_state_path),
            "save_state_size": save_state_size,
            "save_state_sha256": save_state_sha256,
            "save_state_resume": {
                "breakpoint_linear": breakpoint_linear,
                "single_step_stop": step_stop,
                "post_save_stop": final_stop,
                "post_save_registers": final_registers,
                "post_save_state": post_save_state,
                "halted_boundary": True,
                "pre_save_stop": stop,
                "pre_save_registers": registers,
                "immediate_halted": immediate_save is not None,
            },
        }
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    checkpoint_record.update(
        {
            "save_state": str(save_state_path),
            "save_state_size": save_state_size,
            "save_state_sha256": save_state_sha256,
            "save_state_resume": metadata["save_state_resume"],
        }
    )
    return final_stop, final_registers


def checkpoint_save_state_target(
    enabled: bool,
    startup_keys: list[str],
    resume_checkpoint_script: str | None,
    has_post_resume_next_breakpoint: bool,
    state_input_stop_value: str | None = None,
    load_save_state_continue: bool = False,
    save_state_first: bool = False,
) -> str | None:
    if not enabled:
        return None
    if save_state_first:
        if not resume_checkpoint_script:
            raise ValueError(
                "first post-resume save-state requires a resume checkpoint"
            )
        if has_post_resume_next_breakpoint:
            raise ValueError(
                "first post-resume save-state cannot be combined with a "
                "post-resume next breakpoint"
            )
        return "post_resume_first"
    if resume_checkpoint_script:
        if has_post_resume_next_breakpoint:
            return "post_resume_next"
        # A resumed state script can end at an exact halted checkpoint.  The
        # pinned backend can serialize that boundary directly; requiring a
        # second breakpoint only to obtain a reusable save adds an avoidable
        # execution boundary and makes long native routes unnecessarily
        # expensive.
        return "resume_final"
    checkpoint_prefixes = (
        "checkpointstate:",
        "checkpointstatehold:",
        "checkpointstatescript:",
        "checkpointstatescriptfile:",
    )
    if not startup_keys or not startup_keys[-1].startswith(
        checkpoint_prefixes
    ):
        if (
            state_input_stop_value is not None
            and (
                (
                    startup_keys
                    and startup_keys[-1].startswith("rununtilstop:")
                )
                or (load_save_state_continue and not startup_keys)
            )
        ):
            return "state_input_stop"
        raise ValueError(
            "checkpoint save-state requires a state-checkpoint action as "
            "the final startup key"
        )
    return "startup"


def recover_checkpoint_screenshot_side_effects(
    out_dir: Path,
    state_checkpoints: list[dict[str, Any]],
    baseline: set[Path],
    *,
    timeout_seconds: float = 1.0,
) -> int:
    requested = [
        record
        for record in state_checkpoints
        if (
            record.get("screenshot_requested") is True
            and record.get("screenshot_exact_checkpoint") is not True
        )
    ]
    if not requested:
        return 0
    deadline = time.monotonic() + timeout_seconds
    side_effects: list[Path] = []
    while True:
        side_effects = sorted(
            (
                candidate
                for candidate in out_dir.glob("*.png")
                if candidate not in baseline
            ),
            key=lambda candidate: (
                candidate.stat().st_mtime_ns,
                candidate.name,
            ),
        )
        if len(side_effects) >= len(requested):
            break
        if time.monotonic() >= deadline:
            return 0
        time.sleep(0.02)
    if len(side_effects) != len(requested):
        return 0

    recovered = 0
    for record, source in zip(requested, side_effects):
        checkpoint = Path(record["path"])
        destination = checkpoint / "remote_runtime_screen.png"
        data = _read_stable_nonempty_file(source, timeout_seconds)
        if data is None:
            return recovered
        if not destination.exists():
            destination.write_bytes(data)
            recovered += 1
        metadata_path = checkpoint / "remote_runtime_registers.json"
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        metadata["screenshot"] = str(destination)
        if metadata.get("screenshot_error") is None:
            metadata["screenshot_error"] = (
                "deferred backend screenshot side effect; exact checkpoint "
                "alignment is unconfirmed"
            )
        metadata["screenshot_exact_checkpoint"] = False
        metadata["screenshot_deferred_side_effect"] = True
        metadata_path.write_text(
            json.dumps(metadata, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        record["screenshot"] = str(destination)
        record["screenshot_error"] = metadata["screenshot_error"]
        record["screenshot_exact_checkpoint"] = False
        record["screenshot_deferred_side_effect"] = True
    return recovered


def _read_stable_nonempty_file(
    path: Path,
    timeout_seconds: float = 1.0,
) -> bytes | None:
    """Read a backend side-effect file after its writer has finished.

    DOSBox-X can create the PNG directory entry before its encoder has
    flushed the contents.  Treating that transient zero-byte file as a
    screenshot permanently loses the frame, so require a nonzero size that is
    unchanged across a short observation interval.
    """
    if timeout_seconds <= 0:
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            return None
        return data or None
    deadline = time.monotonic() + timeout_seconds
    previous_size: int | None = None
    while time.monotonic() < deadline:
        try:
            size = path.stat().st_size
        except FileNotFoundError:
            time.sleep(0.02)
            continue
        if size > 0 and size == previous_size:
            data = path.read_bytes()
            if data:
                return data
        previous_size = size
        time.sleep(0.02)
    return None


def write_screenshot_provenance_manifest(
    out_dir: Path,
    state_checkpoints: list[dict[str, Any]],
) -> Path | None:
    """Persist machine-readable provenance for checkpoint PNGs.

    This is intentionally backend-agnostic: it records the checkpoint image
    hash and corroborating root side-effect hashes without assuming that a
    direct QMP response or a deferred side effect was used for a particular
    tick.
    """
    records: list[dict[str, Any]] = []
    root_hashes: dict[str, list[str]] = {}
    for source in sorted(out_dir.glob("*.png")):
        data = source.read_bytes()
        root_hashes.setdefault(hashlib.sha256(data).hexdigest(), []).append(
            source.name
        )
    for checkpoint in state_checkpoints:
        checkpoint_path = Path(str(checkpoint["path"]))
        destination = checkpoint_path / "remote_runtime_screen.png"
        if not destination.is_file():
            continue
        data = destination.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        records.append(
            {
                "tick": int(checkpoint.get("value", len(records) + 1)),
                "destination": str(destination),
                "destination_sha256": digest,
                "destination_size": len(data),
                "valid_png": data.startswith(b"\x89PNG\r\n\x1a\n"),
                "matching_root_side_effects": root_hashes.get(digest, []),
                "root_match_count": len(root_hashes.get(digest, [])),
            }
        )
    if not records:
        return None
    manifest = out_dir / "screenshot-provenance-v1.json"
    manifest.write_text(
        json.dumps(
            {
                "format_version": 1,
                "capture": str(out_dir),
                "tick_count": len(records),
                "valid_png_count": sum(item["valid_png"] for item in records),
                "nonempty_count": sum(item["destination_size"] > 0 for item in records),
                "root_side_effect_count": len(list(out_dir.glob("*.png"))),
                "root_hash_match_ticks": sum(
                    item["root_match_count"] > 0 for item in records
                ),
                "method": "stable_nonempty_post_display_screenshot_with_root_side_effect_hash_crosscheck",
                "ticks": records,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return manifest


def qmp_memory_dump(
    qmp: Any,
    address: int,
    size: int,
) -> bytes:
    """Read memory through the bounded path when the backend provides it.

    The small compatibility branch keeps test doubles and third-party QMP
    adapters that only implement ``memdump`` usable.
    """
    reader = getattr(qmp, "memdump_chunked", None)
    if reader is not None:
        return reader(address, size)
    return qmp.memdump(address, size)


def write_state_checkpoint(
    qmp: Any,
    checkpoint_root: Path,
    field_name: str,
    value: int,
    stop: str,
    registers: dict[str, int],
    state: dict[str, int],
    hit_index: int,
    dump_segment_name: str,
    dump_size: int,
    dump_low_memory: bool,
    vga_address: int,
    vga_size: int,
    pgm_header: bytes,
    *,
    capture_vga: bool = True,
    capture_dac: bool = False,
    capture_display: bool = False,
    capture_screenshot: bool = False,
    collision_namespace: str | None = None,
) -> dict[str, Any]:
    checkpoint_path = checkpoint_root / f"{field_name}-{value}"
    if checkpoint_path.exists() and collision_namespace is not None:
        checkpoint_path = (
            checkpoint_root
            / collision_namespace
            / f"{field_name}-{value}"
        )
    checkpoint_path.mkdir(parents=True, exist_ok=False)
    dump_segment_value = registers[dump_segment_name] & 0xFFFF
    dump_linear = dump_segment_value << 4
    dump = qmp_memory_dump(qmp, dump_linear, dump_size)
    vga_dump = (
        qmp_memory_dump(qmp, vga_address, vga_size)
        if capture_vga
        else None
    )
    dac_dump = qmp.dacdump() if capture_dac else None
    display_dump = qmp.displaydump() if capture_display else None
    low_memory_dump = (
        qmp_memory_dump(qmp, 0x00000, 0xA0000)
        if dump_low_memory
        else None
    )

    dump_path = checkpoint_path / "remote_runtime_ds.bin"
    vga_path = checkpoint_path / "remote_runtime_vga.bin"
    vga_pgm_path = checkpoint_path / "remote_runtime_vga.pgm"
    dac_path = checkpoint_path / "remote_runtime_dac.bin"
    display_path = checkpoint_path / "remote_runtime_display.bin"
    low_memory_path = checkpoint_path / "remote_runtime_lowmem.bin"
    screenshot_path = checkpoint_path / "remote_runtime_screen.png"
    registers_path = checkpoint_path / "remote_runtime_registers.json"
    dump_path.write_bytes(dump)
    if vga_dump is not None:
        vga_path.write_bytes(vga_dump)
        vga_pgm_path.write_bytes(pgm_header + vga_dump)
    if dac_dump is not None:
        dac_path.write_bytes(dac_dump["data"])
    if display_dump is not None:
        display_path.write_bytes(display_dump["data"])
    if low_memory_dump is not None:
        low_memory_path.write_bytes(low_memory_dump)
    screenshot_error = (
        capture_optional_screenshot(qmp, screenshot_path)
        if capture_screenshot
        else None
    )
    registers_path.write_text(
        json.dumps(
            {
                "stop": stop,
                "registers": registers,
                "ds_linear": dump_linear,
                "dump_segment": dump_segment_name,
                "dump_segment_value": dump_segment_value,
                "dump": str(dump_path),
                "dump_size": len(dump),
                "low_memory_dump": (
                    str(low_memory_path)
                    if low_memory_dump is not None
                    else None
                ),
                "low_memory_size": (
                    len(low_memory_dump)
                    if low_memory_dump is not None
                    else 0
                ),
                "vga_dump": (
                    str(vga_path)
                    if vga_dump is not None
                    else None
                ),
                "vga_pgm": (
                    str(vga_pgm_path)
                    if vga_dump is not None
                    else None
                ),
                "dac": (
                    {
                        "dump": str(dac_path),
                        "size": len(dac_dump["data"]),
                        "bits": dac_dump["bits"],
                        "pel_mask": dac_dump["pel_mask"],
                        "pel_index": dac_dump["pel_index"],
                        "state": dac_dump["state"],
                        "write_index": dac_dump["write_index"],
                        "read_index": dac_dump["read_index"],
                        "first_changed": dac_dump["first_changed"],
                    }
                    if dac_dump is not None
                    else None
                ),
                "display": (
                    {
                        "dump": str(display_path),
                        "size": len(display_dump["data"]),
                        "width": display_dump["width"],
                        "height": display_dump["height"],
                        "bpp": display_dump["bpp"],
                        "pitch": display_dump["pitch"],
                        "generation": display_dump["generation"],
                        "halt_safe": True,
                        "source": "last_completed_renderer_source_frame",
                    }
                    if display_dump is not None
                    else None
                ),
                "screenshot": (
                    str(screenshot_path)
                    if capture_screenshot and screenshot_error is None
                    else None
                ),
                "screenshot_error": screenshot_error,
                "screenshot_exact_checkpoint": (
                    capture_screenshot and screenshot_error is None
                ),
                "screenshot_deferred_side_effect": False,
                "state_checkpoint": {
                    "field": field_name,
                    "value": value,
                    "matched_hit": hit_index,
                    "state": state,
                },
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return {
        "field": field_name,
        "value": value,
        "matched_hit": hit_index,
        "state": state,
        "path": str(checkpoint_path),
        "display": str(display_path) if display_dump is not None else None,
        "screenshot_requested": capture_screenshot,
        "screenshot": (
            str(screenshot_path)
            if capture_screenshot and screenshot_error is None
            else None
        ),
        "screenshot_error": screenshot_error,
        "screenshot_exact_checkpoint": (
            capture_screenshot and screenshot_error is None
        ),
        "screenshot_deferred_side_effect": False,
    }


def write_vga_dac_sequence_sample(
    sequence_dir: Path,
    index: int,
    vga_data: bytes,
    dac_dump: dict[str, Any],
    *,
    memory_data: bytes | None = None,
    memory_segment: str | None = None,
    memory_linear: int | None = None,
    memory_segment_value: int | None = None,
    memory_cs: int | None = None,
    memory_eip: int | None = None,
) -> dict[str, Any]:
    frame_path = sequence_dir / f"frame_{index:04d}.bin"
    dac_path = sequence_dir / f"frame_{index:04d}.dac.bin"
    frame_path.write_bytes(vga_data)
    dac_data = dac_dump["data"]
    dac_path.write_bytes(dac_data)
    sample: dict[str, Any] = {
        "sha256": hashlib.sha256(vga_data).hexdigest(),
        "path": str(frame_path),
        "dac": {
            "sha256": hashlib.sha256(dac_data).hexdigest(),
            "path": str(dac_path),
            "size": len(dac_data),
            "bits": dac_dump["bits"],
            "pel_mask": dac_dump["pel_mask"],
            "pel_index": dac_dump["pel_index"],
            "state": dac_dump["state"],
            "write_index": dac_dump["write_index"],
            "read_index": dac_dump["read_index"],
            "first_changed": dac_dump["first_changed"],
        },
    }
    if memory_data is not None:
        segment = memory_segment or "memory"
        memory_path = sequence_dir / f"frame_{index:04d}.{segment}.bin"
        memory_path.write_bytes(memory_data)
        sample["memory"] = {
            "segment": segment,
            "sha256": hashlib.sha256(memory_data).hexdigest(),
            "path": str(memory_path),
            "size": len(memory_data),
            "linear": memory_linear,
            "segment_value": memory_segment_value,
            "cs": memory_cs,
            "eip": memory_eip,
        }
    return sample


def write_display_dac_sequence_sample(
    sequence_dir: Path,
    index: int,
    display_dump: dict[str, Any],
    dac_dump: dict[str, Any],
) -> dict[str, Any]:
    """Persist one completed renderer source frame and matching DAC state."""
    display_path = sequence_dir / f"frame_{index:04d}.display.bin"
    dac_path = sequence_dir / f"frame_{index:04d}.dac.bin"
    display_data = display_dump["data"]
    dac_data = dac_dump["data"]
    display_path.write_bytes(display_data)
    dac_path.write_bytes(dac_data)
    return {
        "display": {
            "sha256": hashlib.sha256(display_data).hexdigest(),
            "path": str(display_path),
            "size": len(display_data),
            "width": display_dump["width"],
            "height": display_dump["height"],
            "bpp": display_dump["bpp"],
            "pitch": display_dump["pitch"],
            "generation": display_dump["generation"],
        },
        "dac": {
            "sha256": hashlib.sha256(dac_data).hexdigest(),
            "path": str(dac_path),
            "size": len(dac_data),
            "bits": dac_dump["bits"],
            "pel_mask": dac_dump["pel_mask"],
            "pel_index": dac_dump["pel_index"],
            "state": dac_dump["state"],
            "write_index": dac_dump["write_index"],
            "read_index": dac_dump["read_index"],
            "first_changed": dac_dump["first_changed"],
        },
    }


def write_display_history(
    out_dir: Path,
    start: dict[str, int],
    history: dict[str, Any],
) -> dict[str, Any]:
    """Persist a bounded, halt-retrieved sequence of completed frames."""
    history_dir = out_dir / "post_resume_display_history"
    history_dir.mkdir(parents=True, exist_ok=True)
    frame_records = []
    for index, frame in enumerate(history["frames"]):
        frame_path = history_dir / f"frame_{index:04d}.display.bin"
        frame_data = frame["data"]
        frame_path.write_bytes(frame_data)
        frame_record = {
                "index": index,
                "path": str(frame_path),
                "sha256": hashlib.sha256(frame_data).hexdigest(),
                "size": len(frame_data),
                "width": frame["width"],
                "height": frame["height"],
                "bpp": frame["bpp"],
                "pitch": frame["pitch"],
                "generation": frame["generation"],
            }
        palette_data = frame.get("palette")
        if palette_data is not None:
            palette_path = history_dir / f"frame_{index:04d}.palette.bin"
            palette_path.write_bytes(palette_data)
            frame_record["palette"] = {
                "path": str(palette_path),
                "sha256": hashlib.sha256(palette_data).hexdigest(),
                "size": len(palette_data),
                "bits": 8,
            }
        frame_records.append(frame_record)
    generations = [frame["generation"] for frame in frame_records]
    record = {
        "capacity": history["capacity"],
        "dropped": history["dropped"],
        "start_generation": start["generation"],
        "frame_count": len(frame_records),
        "first_generation": generations[0] if generations else None,
        "last_generation": generations[-1] if generations else None,
        "frames": frame_records,
    }
    manifest_path = out_dir / "post_resume_display_history.json"
    manifest_path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    record["manifest"] = str(manifest_path)
    return record


def should_capture_vga_sequence_screenshot(
    capture_all: bool,
    capture_on_stop: bool,
    stop_sha256: str,
    frame_sha256: str,
) -> bool:
    """Return whether this running VGA sample needs a screenshot."""
    return capture_all or (
        capture_on_stop
        and bool(stop_sha256)
        and frame_sha256 == stop_sha256.lower()
    )


def capture_post_display_screenshot(
    gdb: RspClient,
    qmp: QmpClient,
    timeout: float,
    post_break_segmented: tuple[int, int],
    poke_linear: int,
    poke_bytes: bytes,
    checkpoint_record: dict[str, Any],
    delay: float,
    *,
    primary_breakpoint_installed: bool = True,
) -> None:
    """Freeze the just-completed display pass and capture a running screenshot.

    DOSBox-X's QMP screendump is not reliable while the guest is stopped in
    its GDB loop.  The caller is halted at the state boundary.  We therefore
    step off that boundary, stop at a display-complete instruction, replace
    that instruction with a self-loop while the emulator is running, and
    screendump the frozen frame.  The original bytes and boundary breakpoint
    are restored before returning so a checkpoint series can continue.
    """
    segment, offset = post_break_segmented
    post_backend = pack_segment_offset(segment, offset)
    post_linear = (segment << 4) + offset
    primary = checkpoint_record.get("primary_breakpoint")
    if not isinstance(primary, int):
        raise ValueError("post-display capture requires primary breakpoint")
    if primary_breakpoint_installed:
        gdb.remove_breakpoint(primary)
        gdb.step_nowait()
        gdb.wait_for_stop(timeout)
    gdb.insert_breakpoint(post_backend)
    gdb.continue_nowait()
    gdb.wait_for_stop(timeout)
    gdb.remove_breakpoint(post_backend)
    original = gdb.read_memory(poke_linear, len(poke_bytes))
    metadata_path = Path(checkpoint_record["path"]) / "remote_runtime_registers.json"
    checkpoint_metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    screenshot_path = Path(checkpoint_record["path"]) / "remote_runtime_screen.png"
    screenshot_error: RuntimeError | None = None
    screenshot_deferred_side_effect = False
    post_display_state_error: Exception | None = None
    post_display_state: dict[str, Any] | None = None
    try:
        gdb.write_memory(poke_linear, poke_bytes)
        gdb.continue_nowait()
        time.sleep(delay)
        out_dir = Path(checkpoint_record["path"]).parent.parent
        # DOSBox-X may emit its deferred root PNG while servicing the VRAM
        # memdump.  Snapshot the baseline before that request so an empty
        # screendump response can recover the side effect deterministically.
        before_screens = set(out_dir.glob("*.png"))
        qmp.memdump(0xA0000, 320 * 200)
        screenshot_data: bytes | None = None
        for attempt in range(3):
            try:
                screenshot_data = qmp.screendump()
                if not screenshot_data:
                    raise RuntimeError(
                        "QMP screendump returned an empty decoded payload"
                    )
                screenshot_error = None
                break
            except RuntimeError as exc:
                screenshot_error = exc
                side_effects = sorted(
                    (
                        path
                        for path in out_dir.glob("*.png")
                        if path not in before_screens
                    ),
                    key=lambda path: path.stat().st_mtime_ns,
                )
                for side_effect in reversed(side_effects):
                    screenshot_data = _read_stable_nonempty_file(
                        side_effect,
                        timeout_seconds=1.0,
                    )
                    if screenshot_data is None:
                        continue
                    screenshot_error = None
                    screenshot_deferred_side_effect = True
                    print(
                        "post-display: recovered deferred screendump side effect",
                        flush=True,
                    )
                    break
                time.sleep(0.1)
        if screenshot_data is None:
            raise screenshot_error or RuntimeError("post-display screendump failed")
        screenshot_path.write_bytes(screenshot_data)
    finally:
        gdb.halt(timeout)
        # The primary checkpoint dump is taken before the display pass.  The
        # running self-loop is a separate, exact post-display boundary; retain
        # its canonical data segment and registers so semantic comparisons can
        # use the same boundary as the framebuffer instead of mixing phases.
        try:
            post_registers = gdb.registers()
            dump_segment_name = str(
                checkpoint_metadata.get("dump_segment", "ds")
            )
            dump_segment = post_registers[dump_segment_name] & 0xFFFF
            dump_size = int(checkpoint_metadata.get("dump_size", 0x10000))
            post_dump = qmp.memdump(dump_segment << 4, dump_size)
            checkpoint_path = Path(checkpoint_record["path"])
            post_dump_path = checkpoint_path / "remote_runtime_post_display_ds.bin"
            post_dump_path.write_bytes(post_dump)
            dac = qmp.dacdump()
            post_dac_path = checkpoint_path / "remote_runtime_post_display_dac.bin"
            post_dac_path.write_bytes(dac["data"])
            post_display_state = {
                "registers": post_registers,
                "dump_segment": dump_segment_name,
                "dump_segment_value": dump_segment,
                "ds_linear": dump_segment << 4,
                "dump": str(post_dump_path),
                "dump_size": len(post_dump),
                "stop": "post-display-self-loop",
                "dac": {
                    "dump": str(post_dac_path),
                    "size": len(dac["data"]),
                    "bits": dac["bits"],
                    "pel_mask": dac["pel_mask"],
                    "pel_index": dac["pel_index"],
                    "state": dac["state"],
                    "write_index": dac["write_index"],
                    "read_index": dac["read_index"],
                    "first_changed": dac["first_changed"],
                },
            }
            post_registers_path = (
                checkpoint_path / "remote_runtime_post_display_registers.json"
            )
            post_registers_path.write_text(
                json.dumps(post_display_state, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            post_display_state["registers_file"] = str(post_registers_path)
        except Exception as exc:  # restore the executable even if dumping fails
            post_display_state_error = exc
        gdb.write_memory(poke_linear, original)
        if primary_breakpoint_installed:
            gdb.insert_breakpoint(primary)
    if screenshot_error is not None:
        raise screenshot_error
    if post_display_state_error is not None:
        raise RuntimeError("post-display state dump failed") from post_display_state_error
    checkpoint_record.update(
        {
            "screenshot": str(screenshot_path),
            "screenshot_exact_checkpoint": True,
            "screenshot_post_display_breakpoint": f"{segment:04x}:{offset:04x}",
            "screenshot_post_display_linear": post_linear,
            "screenshot_poke": {
                "address": poke_linear,
                "bytes": poke_bytes.hex(),
                "restored": original.hex(),
            },
            "screenshot_deferred_side_effect": screenshot_deferred_side_effect,
            "post_display_state": post_display_state,
        }
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "screenshot": str(screenshot_path),
            "screenshot_error": None,
            "screenshot_exact_checkpoint": True,
            "screenshot_post_display_breakpoint": f"{segment:04x}:{offset:04x}",
            "screenshot_post_display_linear": post_linear,
            "screenshot_poke": checkpoint_record["screenshot_poke"],
            "screenshot_deferred_side_effect": screenshot_deferred_side_effect,
            "post_display_state": post_display_state,
        }
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def capture_halted_breakpoint_screenshot(
    gdb: RspClient,
    qmp: QmpClient,
    timeout: float,
    breakpoint_backend_address: int,
    breakpoint_linear_address: int,
    vga_address: int,
    vga_size: int,
    checkpoint_record: dict[str, Any],
    delay: float,
    *,
    preserve_memory: list[tuple[int, int]] | None = None,
) -> None:
    """Capture an exact screenshot while preserving a breakpoint series.

    DOSBox-X cannot reliably service QMP screendump while stopped in its GDB
    loop. Replace the halted instruction with a temporary self-loop, let the
    emulator run, capture the stable display, then restore both the instruction
    and breakpoint before the series controller steps to its next hit.
    """
    checkpoint_path = Path(checkpoint_record["path"])
    metadata_path = checkpoint_path / "remote_runtime_registers.json"
    screenshot_path = checkpoint_path / "remote_runtime_screen.png"
    poke_bytes = b"\xeb\xfe"
    gdb.remove_breakpoint(breakpoint_backend_address)
    original = gdb.read_memory(breakpoint_linear_address, len(poke_bytes))
    preserved = [
        (address, gdb.read_memory(address, size))
        for address, size in (preserve_memory or [])
    ]
    preserved_registers = gdb.registers()
    screenshot_error: str | None = None
    try:
        gdb.write_memory(breakpoint_linear_address, poke_bytes)
        gdb.continue_nowait()
        time.sleep(delay)
        qmp.memdump(vga_address, vga_size)
        screenshot_error = capture_optional_screenshot(qmp, screenshot_path)
    finally:
        gdb.halt(timeout)
        for address, data in preserved:
            gdb.write_memory(address, data)
        gdb.write_memory(breakpoint_linear_address, original)
        gdb.write_registers(preserved_registers)
        gdb.insert_breakpoint(breakpoint_backend_address)
    if screenshot_error is not None:
        raise RuntimeError(screenshot_error)
    screenshot_poke = {
        "address": breakpoint_linear_address,
        "bytes": poke_bytes.hex(),
        "restored": original.hex(),
    }
    preserved_memory = [
        {
            "address": address,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for address, data in preserved
    ]
    checkpoint_record.update(
        {
            "screenshot": str(screenshot_path),
            "screenshot_requested": True,
            "screenshot_error": None,
            "screenshot_exact_checkpoint": True,
            "screenshot_poke": screenshot_poke,
            "screenshot_preserved_memory": preserved_memory,
            "screenshot_registers_restored": True,
            "screenshot_deferred_side_effect": False,
        }
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata.update(
        {
            "screenshot": str(screenshot_path),
            "screenshot_error": None,
            "screenshot_exact_checkpoint": True,
            "screenshot_poke": screenshot_poke,
            "screenshot_preserved_memory": preserved_memory,
            "screenshot_registers_restored": True,
            "screenshot_deferred_side_effect": False,
        }
    )
    metadata_path.write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def capture_configured_post_display(
    gdb: RspClient,
    qmp: QmpClient,
    timeout: float,
    post_display_break: tuple[int, int] | None,
    post_display_poke: tuple[int, bytes] | None,
    checkpoint_record: dict[str, Any],
    primary_breakpoint: int,
    delay: float,
    *,
    primary_breakpoint_installed: bool = True,
) -> None:
    """Capture the configured post-display boundary for any checkpoint mode."""
    if post_display_break is None or post_display_poke is None:
        return
    checkpoint_record["primary_breakpoint"] = primary_breakpoint
    capture_post_display_screenshot(
        gdb,
        qmp,
        timeout,
        post_display_break,
        post_display_poke[0],
        post_display_poke[1],
        checkpoint_record,
        delay,
        primary_breakpoint_installed=primary_breakpoint_installed,
    )


def capture_final_post_display(
    gdb: RspClient,
    qmp: QmpClient,
    timeout: float,
    post_display_break: tuple[int, int],
    post_display_poke: tuple[int, bytes],
    out_dir: Path,
    stop: str,
    initial_halt: str | None,
    registers: dict[str, int],
    dump_segment_name: str,
    dump_size: int,
    delay: float,
    value: int | None = None,
    primary_breakpoint: int | None = None,
) -> dict[str, Any]:
    """Capture an exact post-display boundary after the final halt.

    Unlike nested state checkpoints, a final state-input or ordinary halt has
    no checkpoint record on which to hang the running screenshot.  Materialize
    one under ``checkpoints/final-post-display`` so the existing exact capture
    implementation and provenance tooling can be reused.  The caller remains
    halted at the requested final boundary; this helper does not require a
    primary breakpoint to be installed.
    """
    checkpoint_path = out_dir / "checkpoints" / "final-post-display"
    checkpoint_path.mkdir(parents=True, exist_ok=True)
    metadata_path = checkpoint_path / "remote_runtime_registers.json"
    dump_segment = registers[dump_segment_name] & 0xFFFF
    metadata_path.write_text(
        json.dumps(
            {
                "stop": stop,
                "initial_halt": initial_halt,
                "registers": registers,
                "dump_segment": dump_segment_name,
                "dump_segment_value": dump_segment,
                "ds_linear": dump_segment << 4,
                "dump_size": dump_size,
                "final_post_display": True,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    record: dict[str, Any] = {
        "path": str(checkpoint_path),
        "boundary": "final_post_display",
        "stop": stop,
        "primary_breakpoint": (
            primary_breakpoint
            if primary_breakpoint is not None
            else 0
        ),
        "screenshot_requested": True,
    }
    if value is not None:
        record["value"] = value
    capture_post_display_screenshot(
        gdb,
        qmp,
        timeout,
        post_display_break,
        post_display_poke[0],
        post_display_poke[1],
        record,
        delay,
        primary_breakpoint_installed=primary_breakpoint is not None,
    )
    return record


def checkpoint_post_display_enabled(scope: str, boundary: str) -> bool:
    """Return whether post-display work is enabled for this boundary class."""
    if scope == "all":
        return True
    if scope == "post-resume-next":
        return boundary == "post_resume_next"
    raise ValueError(f"unsupported checkpoint post-display scope: {scope!r}")


def capture_post_resume_next_display(
    gdb: RspClient,
    qmp: QmpClient,
    timeout: float,
    post_display_break: tuple[int, int] | None,
    post_display_poke: tuple[int, bytes] | None,
    checkpoint_record: dict[str, Any],
    primary_breakpoint: int,
    delay: float,
) -> None:
    """Capture post-display evidence from a paired resume's next boundary."""
    if post_display_break is None or post_display_poke is None:
        return
    checkpoint_record["primary_breakpoint"] = primary_breakpoint
    capture_configured_post_display(
        gdb,
        qmp,
        timeout,
        post_display_break,
        post_display_poke,
        checkpoint_record,
        primary_breakpoint,
        delay,
    )


def parse_poke(spec: str, regs: dict[str, int]) -> tuple[int, bytes]:
    parts = spec.split(":")
    if len(parts) == 2:
        address_s, hex_s = parts
        address = int(address_s, 0)
    elif len(parts) == 3 and parts[0] in {"ds", "ss"}:
        segment = regs[parts[0]]
        address = (segment << 4) + int(parts[1], 0)
        hex_s = parts[2]
    else:
        raise ValueError(
            "poke must be linear_addr:hexbytes or ds:offset:hexbytes / ss:offset:hexbytes"
        )
    if len(hex_s) % 2:
        raise ValueError(f"poke hex byte string must have even length: {spec!r}")
    return address, bytes.fromhex(hex_s)


def parse_poke_file(spec: str, regs: dict[str, int]) -> tuple[int, Path]:
    parts = spec.split(":", 2)
    if len(parts) == 2:
        address_s, path_s = parts
        address = int(address_s, 0)
    elif len(parts) == 3 and parts[0] in {"ds", "ss"}:
        segment = regs[parts[0]]
        address = (segment << 4) + int(parts[1], 0)
        path_s = parts[2]
    else:
        raise ValueError(
            "poke-file must be linear_addr:path or ds:offset:path / ss:offset:path"
        )
    path = Path(path_s)
    if not path.exists():
        raise FileNotFoundError(f"poke-file path does not exist: {path}")
    return address, path


def interrupted_probe_manifest(args: Any) -> dict[str, Any]:
    """Describe direct controls applied at the initial interrupted stop."""
    return {
        "poke": args.poke,
        "poke_file": args.poke_file,
        "call_near": args.call_near,
        "call_near_break_linear": getattr(args, "call_near_break_linear", None),
        "call_near_break_segmented": getattr(
            args, "call_near_break_segmented", None
        ),
        "call_near_break_offset": getattr(args, "call_near_break_offset", None),
        "call_near_continue_after_return": (
            args.call_near_continue_after_return
        ),
    }


def apply_halted_poke_files(
    gdb: RspClient,
    specs: list[str],
    regs: dict[str, int],
) -> list[dict[str, Any]]:
    writes: list[dict[str, Any]] = []
    for spec in specs:
        address, path = parse_poke_file(spec, regs)
        data = path.read_bytes()
        gdb.write_memory_chunked(address, data)
        writes.append(
            {
                "spec": spec,
                "address": address,
                "path": str(path),
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return writes


def apply_halted_pokes(
    gdb: RspClient,
    specs: list[str],
    regs: dict[str, int],
) -> list[dict[str, Any]]:
    writes: list[dict[str, Any]] = []
    for spec in specs:
        address, data = parse_poke(spec, regs)
        gdb.write_memory_chunked(address, data)
        writes.append(
            {
                "spec": spec,
                "address": address,
                "size": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
            }
        )
    return writes


def apply_post_resume_pokes(
    gdb: RspClient,
    poke_specs: list[str],
    poke_file_specs: list[str],
    regs: dict[str, int],
) -> list[dict[str, Any]]:
    return (
        apply_halted_pokes(gdb, poke_specs, regs)
        + apply_halted_poke_files(gdb, poke_file_specs, regs)
    )


def run_simple_key_actions(
    qmp: QmpClient,
    actions: list[str],
    wave_capture_active: bool = False,
    gdb: RspClient | None = None,
) -> bool:
    for raw_action in actions:
        action = raw_action.strip()
        if len(action) >= 2 and action[0] == action[-1] and action[0] in {"'", '"'}:
            action = action[1:-1]
        if action.startswith("wait:"):
            seconds = float(action.split(":", 1)[1])
            time.sleep(seconds)
            print(f"post-restore wait {seconds:.3f}s", flush=True)
            continue
        if action.startswith("keydown:"):
            qcode = action.split(":", 1)[1]
            if not qcode:
                raise ValueError(f"keydown syntax: keydown:<qcode>, got {action!r}")
            qmp.key_event(qcode, True)
            print(f"post-restore key down {qcode}", flush=True)
            continue
        if action.startswith("keyup:"):
            qcode = action.split(":", 1)[1]
            if not qcode:
                raise ValueError(f"keyup syntax: keyup:<qcode>, got {action!r}")
            qmp.key_event(qcode, False)
            print(f"post-restore key up {qcode}", flush=True)
            continue
        if action.startswith("removebreak:"):
            if gdb is None:
                raise ValueError(
                    "removebreak requires the post-restore GDB connection"
                )
            parts = action.split(":", 2)
            address_spec = parts[1] if len(parts) > 1 else ""
            restore_bytes = (
                bytes.fromhex(parts[2]) if len(parts) == 3 else None
            )
            if restore_bytes is not None and not restore_bytes:
                raise ValueError(
                    "removebreak restore bytes must not be empty"
                )
            try:
                linear_address = parse_dos_integer(address_spec)
            except ValueError as exc:
                raise ValueError(
                    "removebreak syntax: "
                    "removebreak:<linear-address>[:<original-bytes>]"
                ) from exc
            try:
                gdb.remove_breakpoint(linear_address)
            except RuntimeError:
                if restore_bytes is None:
                    raise
                current = gdb.read_memory(linear_address, len(restore_bytes))
                if current == restore_bytes:
                    print(
                        f"post-restore breakpoint already absent at "
                        f"0x{linear_address:05x}",
                        flush=True,
                    )
                elif not current or current[0] != 0xCC:
                    raise RuntimeError(
                        "loaded-state breakpoint removal failed and the "
                        "target bytes are not an INT3"
                    )
                else:
                    gdb.write_memory(linear_address, restore_bytes)
                    print(
                        f"post-restore restored serialized breakpoint bytes "
                        f"at 0x{linear_address:05x}",
                        flush=True,
                    )
            print(
                f"post-restore removed linear breakpoint "
                f"0x{linear_address:05x}",
                flush=True,
            )
            continue
        if action.startswith("tap:"):
            parts = action.split(":")
            if len(parts) not in {2, 3}:
                raise ValueError(f"post-restore tap syntax: tap:<qcode>[:seconds], got {action!r}")
            qcode = parts[1]
            hold_seconds = float(parts[2]) if len(parts) == 3 else 0.15
            qmp.key_hold(qcode, hold_seconds)
            print(f"post-restore tap {qcode} {hold_seconds:.3f}s", flush=True)
            continue
        if action.startswith("hold:"):
            parts = action.split(":")
            if len(parts) != 3:
                raise ValueError(f"post-restore hold syntax: hold:<qcode>:<seconds>, got {action!r}")
            qcode = parts[1]
            hold_seconds = float(parts[2])
            qmp.key_hold(qcode, hold_seconds)
            print(f"post-restore hold {qcode} {hold_seconds:.3f}s", flush=True)
            continue
        if action.startswith("chord:"):
            parts = action.split(":")
            if len(parts) not in {2, 3}:
                raise ValueError(
                    f"post-restore chord syntax: chord:<qcode>+<qcode>[:seconds], got {action!r}"
                )
            qcodes = [qcode for qcode in parts[1].split("+") if qcode]
            hold_seconds = float(parts[2]) if len(parts) == 3 else 0.15
            qmp.key_chord(qcodes, hold_seconds)
            print(
                f"post-restore chord {'+'.join(qcodes)} {hold_seconds:.3f}s",
                flush=True,
            )
            continue
        if action.startswith("capture-wave:"):
            operation = action.split(":", 1)[1]
            if operation not in {"start", "stop"}:
                raise ValueError(
                    f"capture-wave syntax: capture-wave:start|stop, got {action!r}"
                )
            wave_capture_active = operation == "start"
            qmp.capture_wave(wave_capture_active)
            print(f"post-restore capture wave {operation}", flush=True)
            continue
        qmp.key_hold(action, 0.5)
        print(f"post-restore key hold {action} 0.500s", flush=True)
    return wave_capture_active


def wave_file_is_finalized(path: Path) -> bool:
    try:
        size = path.stat().st_size
        if size < 44:
            return False
        with path.open("rb") as source:
            header = source.read(12)
        if header[:4] != b"RIFF" or header[8:12] != b"WAVE":
            return False
        if int.from_bytes(header[4:8], "little") + 8 != size:
            return False
        with wave.open(str(path), "rb") as source:
            source.getparams()
        return True
    except (OSError, EOFError, wave.Error):
        return False


def wait_for_finalized_wave_files(
    directory: Path,
    timeout: float,
) -> list[Path]:
    deadline = time.time() + timeout
    paths: list[Path] = []
    while time.time() < deadline:
        paths = sorted(directory.glob("*.wav"))
        if paths and all(wave_file_is_finalized(path) for path in paths):
            return paths
        time.sleep(0.05)
    pending = ", ".join(path.name for path in paths) or "no WAV files"
    raise RuntimeError(
        f"timed out waiting for finalized wave capture: {pending}"
    )


def parse_state(data: bytes, fields: list[Field]) -> dict[str, int]:
    state: dict[str, int] = {}
    for field in fields:
        value = field.decode(data)
        if value is not None:
            state[field.name] = value
    return state


def read_segment_state(
    gdb: RspClient,
    segment: int,
    fields: list[Field],
) -> dict[str, int]:
    if not 0 <= segment <= 0xFFFF:
        raise ValueError(f"state segment is outside 16-bit range: {segment}")
    segment_base = segment << 4
    state: dict[str, int] = {}
    for field in fields:
        data = gdb.read_memory(
            segment_base + field.offset,
            field.size,
        )
        value = field.decode(data, field.offset)
        if value is None:
            raise RuntimeError(
                f"failed to decode state field {field.name!r}"
            )
        state[field.name] = value
    return state


def breakpoint_stack_snapshot(
    gdb: RspClient,
    registers: dict[str, int],
    size: int = 8,
) -> dict[str, int | str]:
    """Read the near-call return address and a compact halted stack prefix."""
    if size < 2:
        raise ValueError("breakpoint stack snapshot size must be at least two")
    segment = registers["ss"] & 0xFFFF
    offset = registers["esp"] & 0xFFFF
    linear = (segment << 4) + offset
    data = gdb.read_memory(linear, size)
    return {
        "segment": segment,
        "offset": offset,
        "linear": linear,
        "size": len(data),
        "bytes_hex": data.hex(),
        "near_return_offset": int.from_bytes(data[:2], "little"),
    }


def parse_state_predicate(spec: str) -> tuple[str, str, int]:
    import re

    match = re.match(
        r"^(?P<field>[A-Za-z0-9_]+)\s*(?P<op>==|=|!=|>=|<=|>|<)\s*"
        r"(?P<value>-?(?:0x[0-9A-Fa-f]+|\d+))$",
        spec.strip(),
    )
    if not match:
        raise ValueError(
            f"invalid state predicate {spec!r}; use field=value, field!=value, field>=value, etc."
        )
    value_text = match.group("value")
    if value_text.startswith("-0x"):
        value = -int(value_text[3:], 16)
    elif value_text.startswith("0x"):
        value = int(value_text, 16)
    else:
        value = int(value_text, 10)
    op = match.group("op")
    if op == "=":
        op = "=="
    return match.group("field"), op, value


def parse_state_breakpoint_action(
    action: str,
) -> tuple[int, tuple[str, str, int], int]:
    parts = action.split(":", 3)
    if len(parts) != 4 or parts[0] != "breakstate":
        raise ValueError(
            "breakstate action syntax: "
            "breakstate:<linear-address>:<field-predicate>:"
            "<positive-maximum-hit-count>"
        )
    linear_address = int(parts[1], 0)
    predicate = parse_state_predicate(parts[2])
    max_hits = int(parts[3], 0)
    if max_hits < 1:
        raise ValueError(
            "state breakpoint maximum hit count must be positive"
        )
    return linear_address, predicate, max_hits


def parse_segmented_state_breakpoint_action(
    action: str,
) -> tuple[int, tuple[str, str, int], int]:
    parts = action.split(":", 4)
    if len(parts) != 5 or parts[0] != "breakstatesso":
        raise ValueError(
            "breakstatesso action syntax: "
            "breakstatesso:<segment>:<offset>:<field-predicate>:"
            "<positive-maximum-hit-count>"
        )
    backend_address = pack_segment_offset(
        parse_dos_integer(parts[1]),
        parse_dos_integer(parts[2]),
    )
    predicate = parse_state_predicate(parts[3])
    max_hits = int(parts[4], 0)
    if max_hits < 1:
        raise ValueError(
            "state breakpoint maximum hit count must be positive"
        )
    return backend_address, predicate, max_hits


def parse_state_checkpoint_action(
    action: str,
) -> tuple[int, str, list[int], int]:
    parts = action.split(":", 4)
    if len(parts) != 5 or parts[0] != "checkpointstate":
        raise ValueError(
            "checkpointstate action syntax: "
            "checkpointstate:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>"
        )
    linear_address = int(parts[1], 0)
    field_name = parts[2]
    if not field_name or not all(
        character.isalnum() or character == "_"
        for character in field_name
    ):
        raise ValueError("checkpointstate field name is invalid")
    values = [int(value, 0) for value in parts[3].split("+")]
    if not values or len(set(values)) != len(values):
        raise ValueError(
            "checkpointstate values must be a non-empty unique list"
        )
    max_hits = int(parts[4], 0)
    if max_hits < 1:
        raise ValueError(
            "checkpointstate maximum hit count must be positive"
        )
    return linear_address, field_name, values, max_hits


def parse_state_checkpoint_hold_action(
    action: str,
) -> tuple[int, str, list[int], int, str, int, int]:
    parts = action.split(":")
    if len(parts) != 8 or parts[0] != "checkpointstatehold":
        raise ValueError(
            "checkpointstatehold action syntax: "
            "checkpointstatehold:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>:"
            "<qcode>:<press-value>:<release-value>"
        )
    (
        linear_address,
        field_name,
        values,
        max_hits,
    ) = parse_state_checkpoint_action(
        "checkpointstate:" + ":".join(parts[1:5])
    )
    qcode = parts[5]
    qcodes = qcode.split("+")
    if (
        not qcodes
        or any(
            not item
            or not all(
                character.isalnum() or character in {"_", "-"}
                for character in item
            )
            for item in qcodes
        )
        or len(set(qcodes)) != len(qcodes)
    ):
        raise ValueError("checkpointstatehold qcode is invalid")
    press_value = int(parts[6], 0)
    release_value = int(parts[7], 0)
    if press_value not in values or release_value not in values:
        raise ValueError(
            "checkpointstatehold press and release values "
            "must both be checkpoint values"
        )
    if values.index(press_value) >= values.index(release_value):
        raise ValueError(
            "checkpointstatehold press value must precede release value"
        )
    return (
        linear_address,
        field_name,
        values,
        max_hits,
        qcode,
        press_value,
        release_value,
    )


def parse_state_checkpoint_script_action(
    action: str,
) -> tuple[
    int,
    str,
    list[int],
    int,
    list[tuple[int, bool, list[str]]],
]:
    parts = action.split(":")
    if len(parts) != 6 or parts[0] != "checkpointstatescript":
        raise ValueError(
            "checkpointstatescript action syntax: "
            "checkpointstatescript:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>:"
            "<value>=down|up.<qcode>[+<qcode>...]"
            "[~<value>=down|up.<qcode>[+<qcode>...]...]"
        )
    (
        linear_address,
        field_name,
        values,
        max_hits,
    ) = parse_state_checkpoint_action(
        "checkpointstate:" + ":".join(parts[1:5])
    )
    events: list[tuple[int, bool, list[str]]] = []
    for event_text in parts[5].split("~"):
        value, pressed, qcodes = parse_state_input_event(event_text)
        if value < min(values) or value > max(values):
            raise ValueError("checkpointstatescript event is invalid")
        events.append((value, pressed, qcodes))
    if not events:
        raise ValueError("checkpointstatescript requires at least one event")
    validate_state_input_events(events)
    return linear_address, field_name, values, max_hits, events


def parse_state_checkpoint_script_file_action(
    action: str,
) -> tuple[int, str, list[int], int]:
    parts = action.split(":")
    if len(parts) != 5 or parts[0] != "checkpointstatescriptfile":
        raise ValueError(
            "checkpointstatescriptfile action syntax: "
            "checkpointstatescriptfile:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>"
        )
    return parse_state_checkpoint_action(
        "checkpointstate:" + ":".join(parts[1:])
    )


def parse_state_input_event(
    event_text: str,
) -> tuple[int, bool, list[str]]:
    assignment = event_text.split("=", 1)
    if len(assignment) != 2:
        raise ValueError("state input script event is invalid")
    try:
        value = int(assignment[0], 0)
    except ValueError as exc:
        raise ValueError("state input script event value is invalid") from exc
    transition = assignment[1].split(".", 1)
    if len(transition) != 2 or transition[0] not in {"down", "up"}:
        raise ValueError("state input script transition is invalid")
    qcodes = transition[1].split("+")
    if (
        not qcodes
        or any(
            not qcode
            or not all(
                character.isalnum() or character in {"_", "-"}
                for character in qcode
            )
            for qcode in qcodes
        )
        or len(set(qcodes)) != len(qcodes)
    ):
        raise ValueError("state input script qcode is invalid")
    return value, transition[0] == "down", qcodes


def state_input_initial_held_qcodes(
    metadata: dict[str, str],
) -> list[str]:
    encoded = metadata.get("initial_held_qcodes", "")
    if not encoded:
        return []
    qcodes = encoded.split("+")
    if (
        any(
            not qcode
            or not all(
                character.isalnum() or character in {"_", "-"}
                for character in qcode
            )
            for qcode in qcodes
        )
        or len(set(qcodes)) != len(qcodes)
    ):
        raise ValueError("state input initial held qcodes are invalid")
    return qcodes


def state_input_preapplied_value(
    metadata: dict[str, str],
) -> int | None:
    encoded = metadata.get("preapplied_through")
    if encoded is None:
        return None
    try:
        value = int(encoded, 0)
    except ValueError as exc:
        raise ValueError("state input preapplied value is invalid") from exc
    if value < 0:
        raise ValueError("state input preapplied value is invalid")
    return value


def validate_state_input_events(
    events: list[tuple[int, bool, list[str]]],
    *,
    initial_held_qcodes: list[str] | None = None,
) -> None:
    if not events:
        raise ValueError("state input script requires at least one event")
    held = set(initial_held_qcodes or [])
    previous_value: int | None = None
    for value, pressed, qcodes in events:
        if previous_value is not None and value < previous_value:
            raise ValueError("state input script events must be value ordered")
        previous_value = value
        for qcode in qcodes:
            if pressed:
                if qcode in held:
                    raise ValueError(
                        "state input script presses an already held qcode"
                    )
                held.add(qcode)
            else:
                if qcode not in held:
                    raise ValueError(
                        "state input script releases an unheld qcode"
                    )
                held.remove(qcode)
    if held:
        raise ValueError("state input script must release every held qcode")


def load_state_input_script(
    path: Path,
) -> tuple[dict[str, str], list[tuple[int, bool, list[str]]]]:
    lines = path.read_text(encoding="utf-8-sig").splitlines()
    content = [
        (line_number, line.strip())
        for line_number, line in enumerate(lines, 1)
        if line.strip()
    ]
    if not content or content[0][1] != "dos-re-state-input-script-v1":
        raise ValueError(
            f"{path}: state input script requires "
            "dos-re-state-input-script-v1"
        )
    metadata: dict[str, str] = {}
    events: list[tuple[int, bool, list[str]]] = []
    for line_number, line in content[1:]:
        if line.startswith("#"):
            assignment = line[1:].strip().split("=", 1)
            if (
                len(assignment) != 2
                or not assignment[0].strip()
                or assignment[0].strip() in metadata
            ):
                raise ValueError(
                    f"{path}:{line_number}: invalid state input metadata"
                )
            metadata[assignment[0].strip()] = assignment[1].strip()
            continue
        try:
            events.append(parse_state_input_event(line))
        except ValueError as exc:
            raise ValueError(f"{path}:{line_number}: {exc}") from exc
    validate_state_input_events(
        events,
        initial_held_qcodes=state_input_initial_held_qcodes(metadata),
    )
    return metadata, events


def replay_resumed_script_transition(
    qmp: Any,
    events: list[tuple[int, bool, list[str]]],
    value: int,
    owner: str = "controller",
) -> list[tuple[str, bool]]:
    """Apply one resumed-script transition through its sole input owner.

    The patched backend can consume the state input script at the guest hook.
    In that mode the controller observes checkpoints only; replaying the same
    transition over QMP would enqueue a second scan-code transition.
    """
    if owner not in {"controller", "backend"}:
        raise ValueError("resume script event owner is invalid")
    if owner == "backend":
        return []
    applied: list[tuple[str, bool]] = []
    for event_value, pressed, qcodes in events:
        if event_value != value:
            continue
        ordered_qcodes = qcodes if pressed else list(reversed(qcodes))
        for qcode in ordered_qcodes:
            qmp.key_event(qcode, pressed)
            applied.append((qcode, pressed))
    return applied


def merged_state_script_values(
    capture_values: list[int],
    events: list[tuple[int, bool, list[str]]],
) -> list[int]:
    if (
        not capture_values
        or any(
            right <= left
            for left, right in zip(capture_values, capture_values[1:])
        )
    ):
        raise ValueError(
            "state input scripts require strictly increasing checkpoint values"
        )
    event_values = [value for value, _pressed, _qcodes in events]
    if any(value < capture_values[0] for value in event_values):
        raise ValueError(
            "state input script cannot begin before the first checkpoint"
        )
    observed_event_values = {
        value
        for value in event_values
        if value <= capture_values[-1]
    }
    return sorted(set(capture_values) | observed_event_values)


def resumed_state_script_plan(
    capture_values: list[int],
    events: list[tuple[int, bool, list[str]]],
) -> tuple[list[int], list[tuple[int, bool, list[str]]]]:
    observed_values, resumed_events, initial_held = (
        resumed_state_script_plan_with_held(capture_values, events)
    )
    if initial_held:
        raise ValueError(
            "resumed state input scripts require a neutral keyboard boundary; "
            f"held before {capture_values[0]}: "
            f"{', '.join(initial_held)}"
        )
    return observed_values, resumed_events


def resumed_state_script_plan_with_held(
    capture_values: list[int],
    events: list[tuple[int, bool, list[str]]],
    *,
    initial_held_qcodes: list[str] | None = None,
) -> tuple[
    list[int],
    list[tuple[int, bool, list[str]]],
    list[str],
]:
    if (
        not capture_values
        or any(
            right <= left
            for left, right in zip(capture_values, capture_values[1:])
        )
    ):
        raise ValueError(
            "state input scripts require strictly increasing checkpoint values"
        )
    first_value = capture_values[0]
    last_value = capture_values[-1]
    # The script metadata describes the keyboard state at the beginning of
    # the movie.  Reconstruct the held set at the first captured boundary by
    # applying only transitions that precede that boundary.  Callers that do
    # not provide metadata retain the historical empty-state behavior.
    held: set[str] = set(initial_held_qcodes or [])
    for value, pressed, qcodes in events:
        if value >= first_value:
            break
        for qcode in qcodes:
            if pressed:
                held.add(qcode)
            else:
                held.remove(qcode)
    resumed_events = [
        event
        for event in events
        if first_value <= event[0] <= last_value
    ]
    return (
        merged_state_script_values(capture_values, resumed_events),
        resumed_events,
        sorted(held),
    )


def resumed_state_checkpoint_plan(
    action: str,
    events: list[tuple[int, bool, list[str]]],
    *,
    initial_held_qcodes: list[str] | None = None,
) -> tuple[
    int,
    str,
    list[int],
    list[int],
    int,
    list[tuple[int, bool, list[str]]],
    list[str],
]:
    if action.startswith("checkpointstate:"):
        linear_address, field_name, capture_values, max_hits = (
            parse_state_checkpoint_action(action)
        )
        return (
            linear_address,
            field_name,
            capture_values,
            capture_values,
            max_hits,
            [],
            [],
        )
    if action.startswith("checkpointstatescriptfile:"):
        linear_address, field_name, capture_values, max_hits = (
            parse_state_checkpoint_script_file_action(action)
        )
        observed_values, resumed_events, initial_held = (
            resumed_state_script_plan_with_held(
                capture_values,
                events,
                initial_held_qcodes=initial_held_qcodes,
            )
        )
        return (
            linear_address,
            field_name,
            capture_values,
            observed_values,
            max_hits,
            resumed_events,
            initial_held,
        )
    raise ValueError(
        "resume checkpoint action must be checkpointstate or "
        "checkpointstatescriptfile"
    )


def prepare_restore_halt(
    gdb: RspClient,
    timeout: float,
    halted_stop: str | None,
    halted_regs: dict[str, int] | None,
) -> tuple[str, dict[str, int]]:
    if halted_regs is not None:
        return halted_stop or "already-halted", halted_regs
    stop = gdb.halt(timeout)
    return stop, gdb.registers()


def validate_resume_bootstrap(
    registers: dict[str, int],
    state: dict[str, int],
    field_name: str,
    first_value: int,
    next_linear: int,
    *,
    full_state_loaded: bool,
) -> None:
    if not full_state_loaded and registers["eip"] != next_linear:
        raise ValueError(
            "resume bootstrap stopped at the wrong next instruction: "
            f"expected 0x{next_linear:05x}, observed "
            f"0x{registers['eip']:05x}"
        )
    if state.get(field_name) != first_value:
        raise ValueError(
            "restored checkpoint state does not match "
            f"{field_name}={first_value}: "
            f"{state.get(field_name)!r}"
        )


def full_state_resume_remaining_values(
    actual_value: int,
    observed_values: list[int],
    input_events: list[tuple[int, bool, list[str]]],
) -> list[int]:
    if not observed_values:
        raise ValueError("full-state resume requires observed values")
    first_value = observed_values[0]
    final_value = observed_values[-1]
    if not first_value <= actual_value <= final_value:
        raise ValueError(
            "loaded full-state value is outside the resume interval: "
            f"{actual_value} not in [{first_value}, {final_value}]"
        )
    # An event exactly at the restored boundary can be applied after the
    # machine is loaded.  If the save has drifted beyond the first requested
    # boundary, however, even an event at that first boundary is already in
    # the crossed interval and cannot be replayed safely without knowing
    # whether the save already includes its effects.
    missed_events = [
        value
        for value, _pressed, _qcodes in input_events
        if first_value <= value < actual_value
    ]
    if missed_events:
        raise ValueError(
            "loaded full-state drift crossed a missed input event at "
            f"{sorted(set(missed_events))}"
        )
    return [value for value in observed_values if value > actual_value]


def stop_on_state_checkpoints(
    gdb: RspClient,
    linear_address: int,
    field_name: str,
    values: list[int],
    max_hits: int,
    timeout: float,
    read_state: Callable[[dict[str, int]], dict[str, int]],
    capture_match: Callable[
        [int, str, dict[str, int], dict[str, int], int],
        None,
    ],
    after_capture: Callable[[int], None] | None = None,
    initially_halted: bool = False,
    side_breakpoint: tuple[int, int] | None = None,
    side_capture: Callable[
        [int, str, dict[str, int]],
        None,
    ] | None = None,
    side_max_hits: int | None = None,
    side_start_value: int | None = None,
) -> tuple[str, dict[str, int], dict[str, int], int]:
    if not values:
        raise ValueError("state checkpoint values must not be empty")
    if max_hits < 1:
        raise ValueError("state checkpoint maximum hit count must be positive")
    if side_breakpoint is not None and side_capture is None:
        raise ValueError("side breakpoint requires a capture callback")
    if side_max_hits is not None and side_max_hits < 1:
        raise ValueError("side breakpoint maximum hit count must be positive")
    if side_max_hits is not None and side_breakpoint is None:
        raise ValueError("side breakpoint maximum requires a side breakpoint")
    if side_start_value is not None and side_start_value < 0:
        raise ValueError("side breakpoint start value must be non-negative")
    if side_start_value is not None and side_breakpoint is None:
        raise ValueError("side breakpoint start requires a side breakpoint")
    if side_breakpoint is not None and side_breakpoint[0] == linear_address:
        raise ValueError("side breakpoint must differ from state checkpoint")
    if not initially_halted:
        gdb.halt(timeout)
    gdb.insert_breakpoint(linear_address)
    if side_breakpoint is not None:
        side_backend_address, side_expected_eip = side_breakpoint
        side_active = side_start_value is None
        if side_active:
            gdb.insert_breakpoint(side_backend_address)
    else:
        side_backend_address = side_expected_eip = None
        side_active = False
    side_exhausted = False
    next_value_index = 0
    primary_hit_index = 0
    side_hit_index = 0
    while primary_hit_index < max_hits:
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        registers = gdb.registers()
        if side_active and registers["eip"] == side_expected_eip:
            side_hit_index += 1
            side_capture(side_hit_index, stop, registers)
            if side_max_hits is not None and side_hit_index >= side_max_hits:
                gdb.remove_breakpoint(side_backend_address)
                side_active = False
                side_backend_address = None
                side_exhausted = True
                continue
            gdb.remove_breakpoint(side_backend_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(side_backend_address)
            continue
        primary_hit_index += 1
        state = read_state(registers)
        if field_name not in state:
            raise ValueError(
                f"state checkpoint field {field_name!r} is missing"
            )
        value = values[next_value_index]
        if state[field_name] == value:
            capture_match(
                value,
                stop,
                registers,
                state,
                primary_hit_index,
            )
            if after_capture is not None:
                after_capture(value)
            next_value_index += 1
            if next_value_index == len(values):
                if side_active and side_backend_address is not None:
                    gdb.remove_breakpoint(side_backend_address)
                return stop, registers, state, primary_hit_index
        if (
            not side_active
            and not side_exhausted
            and side_breakpoint is not None
            and side_start_value is not None
            and state[field_name] >= side_start_value
        ):
            side_backend_address, side_expected_eip = side_breakpoint
            gdb.insert_breakpoint(side_backend_address)
            side_active = True
        if primary_hit_index < max_hits:
            gdb.remove_breakpoint(linear_address)
            gdb.step_nowait()
            gdb.wait_for_stop(timeout)
            gdb.insert_breakpoint(linear_address)
    remaining = values[next_value_index:]
    raise TimeoutError(
        f"state checkpoints for {field_name} did not reach "
        f"{remaining!r} within {max_hits} hits at "
        f"0x{linear_address:05x}"
    )


def predicate_passed(actual: int, op: str, expected: int) -> bool:
    if op == "==":
        return actual == expected
    if op == "!=":
        return actual != expected
    if op == ">=":
        return actual >= expected
    if op == "<=":
        return actual <= expected
    if op == ">":
        return actual > expected
    if op == "<":
        return actual < expected
    raise ValueError(f"unsupported predicate operator {op!r}")


def evaluate_state_predicates(
    state: dict[str, int], predicates: list[tuple[str, str, int]]
) -> list[str]:
    failures: list[str] = []
    for field, op, expected in predicates:
        if field not in state:
            failures.append(f"{field} missing")
            continue
        actual = state[field]
        if not predicate_passed(actual, op, expected):
            failures.append(f"{field}={actual} does not satisfy {op}{expected}")
    return failures


def format_state_predicates(predicates: list[tuple[str, str, int]]) -> str:
    return ",".join(f"{field}{op}{value}" for field, op, value in predicates)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--gdb-port", type=int, default=2159)
    parser.add_argument("--qmp-port", type=int, default=4444)
    parser.add_argument(
        "--break-linear",
        type=lambda s: int(s, 0),
        help="Insert a GDB software breakpoint at a linear guest address before continuing.",
    )
    parser.add_argument("--out-dir", type=Path, required=True)
    parser.add_argument(
        "--state-schema",
        type=Path,
        help="JSON memory-field schema used by --wait-state.",
    )
    parser.add_argument(
        "--screen-signatures",
        type=Path,
        help="JSON screen signatures used by waitvga, waitnotvga, and drivevga.",
    )
    parser.add_argument("--vga-address", type=lambda s: int(s, 0), default=0xA0000)
    parser.add_argument("--vga-width", type=int, default=320)
    parser.add_argument("--vga-height", type=int, default=200)
    parser.add_argument("--startup-delay", type=float, default=3.0)
    parser.add_argument(
        "--startup-key",
        action="append",
        default=[],
        help=(
            "Startup action; repeatable. Supports wait:<s>, "
            "waitvga:<state>:<s>[:<interval>], "
            "waitnotvga:<state>:<s>[:<interval>], "
             "drivevga:<state>:<timeout>:<qcode>[:hold][:interval], "
             "runfor:<positive-seconds>, "
             "runtap:<qcode>[:<positive-seconds>], "
             "rununtilstop:<positive-timeout-seconds>, "
             "hold:<qcode>:<s>, tap:<qcode>[:s], keydown:<qcode>, keyup:<qcode>, "
             "break:<linear-address>, "
             "breaknth:<linear-address>:<positive-hit-count>, "
             "breakstate:<linear-address>:<field-predicate>:<positive-maximum-hit-count>, "
             "breakstatesso:<segment>:<offset>:<field-predicate>:<positive-maximum-hit-count>, "
             "checkpointstate:<linear-address>:<field>:<value>[+<value>...]:"
             "<positive-maximum-hit-count>, "
             "checkpointstatehold:<linear-address>:<field>:"
             "<value>[+<value>...]:<positive-maximum-hit-count>:"
             "<qcode>:<press-value>:<release-value>, "
             "checkpointstatescript:<linear-address>:<field>:"
             "<value>[+<value>...]:<positive-maximum-hit-count>:"
             "<value>=down|up.<qcode>[+<qcode>...][~...], "
             "checkpointstatescriptfile:<linear-address>:<field>:"
             "<value>[+<value>...]:<positive-maximum-hit-count> "
             "(requires --input-script), "
             "clearbreak:<linear-address>, "
             "removebreak:<linear-address>, "
             "removebreakso:<segment>:<offset>, "
             "continuebreakso:<segment>:<offset>, "
             "breakwaithaltedso:<segment>:<offset>, "
             "breakso:<segment>:<offset>, "
            "breaksonth:<segment>:<offset>:<positive-hit-count>, "
            "poke:<linear-address>:<hexbytes>, "
            "pokehalted:<linear-address>:<hexbytes>, "
            "writehalted:<linear-address>:<hexbytes>, "
            "capture-wave:start|stop, or bare qcode."
        ),
    )
    parser.add_argument("--poke", action="append", default=[],
                        help="Write memory before final delay. Forms: linear:hexbytes, ds:offset:hexbytes, ss:offset:hexbytes")
    parser.add_argument("--poke-file", action="append", default=[],
                        help="Write a binary file before final delay. Forms: linear:path, ds:offset:path, ss:offset:path")
    parser.add_argument("--restore-registers", type=Path,
                        help="Restore registers from a remote_runtime_registers.json file after pokes")
    parser.add_argument("--call-near", type=lambda s: int(s, 0),
                        help="Push current IP and continue at a near function offset in the current CS")
    parser.add_argument(
        "--call-near-break-linear",
        type=lambda s: int(s, 0),
        help=(
            "After --call-near, continue until this linear guest breakpoint "
            "inside the called function and capture the halted boundary."
        ),
    )
    parser.add_argument(
        "--call-near-break-segmented",
        help=(
            "After --call-near, continue until this real-mode "
            "<segment>:<offset> breakpoint inside the called function "
            "and capture the halted boundary."
        ),
    )
    parser.add_argument(
        "--call-near-break-offset",
        type=lambda s: int(s, 0),
        help=(
            "After --call-near, continue until this instruction offset in "
            "the live current CS and capture the halted boundary. The "
            "backend address is derived from the observed post-call EIP."
        ),
    )
    parser.add_argument(
        "--call-near-continue-after-return",
        action="store_true",
        help=(
            "After --call-near stops again at its original breakpoint, "
            "remove that breakpoint, step the return instruction, and "
            "continue for the normal final delay"
        ),
    )
    parser.add_argument("--halt-after-poke", action="store_true",
                        help="Capture immediately after pokes/register restore instead of continuing")
    parser.add_argument(
        "--post-restore-key",
        action="append",
        default=[],
        help=(
            "After state restore, send wait/tap/hold/key actions; "
            "removebreak:<linear-address>[:<original-bytes>] clears a "
            "breakpoint serialized in the loaded state"
        ),
    )
    parser.add_argument(
        "--resume-checkpoint-script",
        help=(
            "From the current halted state, optionally after state-file "
            "pokes, capture and continue at state boundaries. Syntax: "
            "checkpointstate:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>, or "
            "checkpointstatescriptfile with the same fields. The latter "
            "requires --input-script; held keys at the resume boundary are "
            "derived from earlier script events and restored automatically."
        ),
    )
    parser.add_argument(
        "--resume-next-linear",
        type=lambda value: int(value, 0),
        help=(
            "Known next instruction after the resume bootstrap clears its "
            "breakpoint. Required with --resume-checkpoint-script."
        ),
    )
    parser.add_argument(
        "--state-side-break-segmented",
        "--resume-side-break-segmented",
        "--checkpoint-side-break-segmented",
        dest="state_side_break_segmented",
        help=(
            "While a state checkpoint loop runs, trace a second real-mode "
            "<segment>:<offset> breakpoint and associate each hit with the "
            "current checkpoint state."
        ),
    )
    parser.add_argument(
        "--state-side-break-max-hits",
        type=int,
        default=0,
        help=(
            "Stop tracing the side breakpoint after this many hits while "
            "continuing the primary state checkpoint loop; zero is unlimited."
        ),
    )
    parser.add_argument(
        "--state-side-break-start-value",
        type=int,
        default=0,
        help=(
            "Arm the side breakpoint only after the primary state field "
            "reaches this value; zero arms it immediately."
        ),
    )
    parser.add_argument(
        "--post-resume-break-linear",
        type=lambda value: int(value, 0),
        help=(
            "After --resume-checkpoint-script reaches its final state, "
            "continue to a linear breakpoint."
        ),
    )
    parser.add_argument(
        "--post-resume-break-segmented",
        help=(
            "After --resume-checkpoint-script reaches its final state, "
            "continue to a real-mode <segment>:<offset> breakpoint."
        ),
    )
    parser.add_argument(
        "--post-resume-break-hit-count",
        type=int,
        default=1,
        help=(
            "Stop on this positive hit of --post-resume-break-linear "
            "(default: 1)."
        ),
    )
    parser.add_argument(
        "--post-resume-break-hit-series",
        help=(
            "Capture several strictly increasing positive hits of the first "
            "post-resume breakpoint in one process, for example 1,4,12. "
            "Each hit is written as a nested checkpoint."
        ),
    )
    parser.add_argument(
        "--post-resume-poke",
        action="append",
        default=[],
        help=(
            "Write inline hex bytes before continuing. With a post-resume "
            "next breakpoint, continue flag, or first-boundary save, writes "
            "occur at the first post-resume breakpoint. Otherwise, writes "
            "occur at the final resumed checkpoint before continuing to the "
            "first post-resume breakpoint. Uses the same forms as --poke."
        ),
    )
    parser.add_argument(
        "--post-resume-display-history-capacity",
        type=int,
        default=0,
        help=(
            "Before continuing from the final resumed state checkpoint, "
            "retain up to this many completed renderer source frames and "
            "write them after the first post-resume breakpoint; zero disables."
        ),
    )
    parser.add_argument(
        "--resume-script-event-owner",
        choices=("controller", "backend"),
        default="controller",
        help=(
            "Component that applies checkpointstatescriptfile key "
            "transitions. Use backend when the pinned backend already "
            "consumes --input-script at the guest-state hook."
        ),
    )
    parser.add_argument(
        "--state-side-break-poke",
        action="append",
        default=[],
        help=(
            "At every traced side-breakpoint hit, write a halted-state poke "
            "before reading and recording checkpoint state. Repeatable; uses "
            "the same linear_addr:hexbytes or ds/ss syntax as --poke."
        ),
    )
    parser.add_argument(
        "--post-resume-poke-file",
        action="append",
        default=[],
        help=(
            "Write a binary file at the same boundary selected for "
            "--post-resume-poke. Uses the same forms as --poke-file."
        ),
    )
    parser.add_argument(
        "--post-resume-continue-after-poke",
        action="store_true",
        help=(
            "At the first post-resume breakpoint, apply "
            "--post-resume-poke-file writes, clear the breakpoint, and "
            "continue without requiring a second breakpoint."
        ),
    )
    parser.add_argument(
        "--post-resume-next-break-linear",
        type=lambda value: int(value, 0),
        help=(
            "Step off the first post-resume breakpoint and stop at this "
            "linear breakpoint, after any --post-resume-poke-file writes."
        ),
    )
    parser.add_argument(
        "--post-resume-next-break-segmented",
        help=(
            "Step off the first post-resume breakpoint and stop at this "
            "real-mode <segment>:<offset> breakpoint, after any "
            "--post-resume-poke-file writes."
        ),
    )
    parser.add_argument(
        "--post-resume-next-break-hit-count",
        type=int,
        default=1,
        help=(
            "Stop on this positive hit of --post-resume-next-break-* "
            "(default: 1)."
        ),
    )
    parser.add_argument("--dump-low-memory", action="store_true",
                        help="Also dump conventional memory 0x00000..0x9ffff for snapshot restore")
    parser.add_argument(
        "--omit-checkpoint-vga",
        action="store_true",
        help=(
            "Do not write VGA artifacts for nested state checkpoints. "
            "The final capture still includes VGA evidence."
        ),
    )
    parser.add_argument(
        "--post-resume-continue",
        action="store_true",
        help=(
            "Clear the first post-resume breakpoint and continue without "
            "mutating guest state. Useful for a running VGA/DAC/audio "
            "sequence anchored at that boundary."
        ),
    )
    parser.add_argument(
        "--checkpoint-dac",
        action="store_true",
        help="Include a 768-byte DAC dump in nested state checkpoints.",
    )
    parser.add_argument(
        "--checkpoint-displaydump",
        action="store_true",
        help=(
            "Include the backend's last completed logical source frame in "
            "nested checkpoints without resuming a halted guest."
        ),
    )
    parser.add_argument(
        "--checkpoint-screenshot",
        action="store_true",
        help=(
            "Capture a QMP screenshot while halted at each nested state "
            "checkpoint."
        ),
    )
    parser.add_argument(
        "--checkpoint-post-display-break-segmented",
        help=(
            "For each state checkpoint, capture an exact running screenshot "
            "after resuming to this <segment>:<offset> display boundary."
        ),
    )
    parser.add_argument(
        "--checkpoint-post-display-poke",
        help=(
            "Linear address and hex bytes for the temporary self-loop used "
            "by --checkpoint-post-display-break-segmented."
        ),
    )
    parser.add_argument(
        "--checkpoint-post-display-delay",
        type=float,
        default=0.05,
        help="Seconds to run the post-display self-loop before screendump.",
    )
    parser.add_argument(
        "--checkpoint-post-display-scope",
        choices=("all", "post-resume-next"),
        default="all",
        help=(
            "Limit exact post-display work to all nested state checkpoints "
            "or only the paired post-resume next boundary (default: all)."
        ),
    )
    parser.add_argument(
        "--checkpoint-screenshot-preserve-memory",
        action="append",
        default=[],
        metavar="LINEAR:SIZE",
        help=(
            "Restore this guest memory region after the temporary running "
            "self-loop used for each checkpoint screenshot. Repeat for "
            "additional regions."
        ),
    )
    parser.add_argument(
        "--post-resume-next-break-hit-series",
        help=(
            "Capture an increasing comma-separated series of positive hit "
            "ordinals at --post-resume-next-break-* after the first "
            "boundary and any post-resume pokes, for example 1,4,12. "
            "Each requested hit is written as a nested checkpoint."
        ),
    )
    parser.add_argument(
        "--final-post-display-break-segmented",
        help=(
            "After the final halt, capture an exact running screenshot at "
            "this <segment>:<offset> display boundary."
        ),
    )
    parser.add_argument(
        "--final-post-display-poke",
        help=(
            "Linear address and hex bytes for the temporary self-loop used "
            "by --final-post-display-break-segmented."
        ),
    )
    parser.add_argument(
        "--final-post-display-delay",
        type=float,
        default=0.05,
        help="Seconds to run the final post-display self-loop before screendump.",
    )
    parser.add_argument(
        "--final-post-display-value",
        type=int,
        help=(
            "Optional logical state value associated with the final "
            "post-display boundary, recorded in checkpoint provenance."
        ),
    )
    parser.add_argument(
        "--checkpoint-save-state",
        action="store_true",
        help=(
            "Write a full DOSBox-X emulator save state at the final nested "
            "startup checkpoint. This briefly releases the stopped CPU, so "
            "the checkpoint action must be the final startup action. The "
            "state is backend/configuration specific."
        ),
    )
    parser.add_argument(
        "--load-save-state",
        type=Path,
        help=(
            "Load a full DOSBox-X emulator save state before attaching the "
            "debugger. The state must match the pinned backend and runtime "
            "configuration."
        ),
    )
    parser.add_argument(
        "--load-save-state-paused",
        action="store_true",
        help=(
            "Use the pinned backend's main-thread load-and-halt operation; "
            "the loaded machine remains at an exact debugger boundary until "
            "the capture resumes it."
        ),
    )
    parser.add_argument(
        "--checkpoint-save-state-first",
        action="store_true",
        help=(
            "Save a full DOSBox-X emulator state at the first post-resume "
            "boundary, before advancing to a post-resume next breakpoint."
        ),
    )
    parser.add_argument(
        "--load-save-state-continue",
        action="store_true",
        help=(
            "After loading --load-save-state, continue the guest until the "
            "configured state-input stop or another normal capture boundary. "
            "This is useful for fast state-input replays without debugger "
            "stops at every scripted transition."
        ),
    )
    parser.add_argument(
        "--load-save-state-ready-screen",
        help=(
            "Before loading a full emulator state, wait for this classified "
            "guest screen so DOSBox-X has completed normal initialization."
        ),
    )
    parser.add_argument(
        "--load-save-state-ready-timeout",
        type=float,
        default=45.0,
    )
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--delay", type=float, default=4.0)
    parser.add_argument(
        "--wait-state",
        action="append",
        default=[],
        help="Schema field predicate to wait for after startup/pokes, e.g. frame_tick=3132. Repeatable.",
    )
    parser.add_argument(
        "--post-wait-key",
        action="append",
        default=[],
        help=(
            "QMP key action to queue after a wait-state match and before "
            "the resumed capture (repeatable; supports tap:/hold:/wait:)."
        ),
    )
    parser.add_argument("--wait-state-timeout", type=float, default=30.0)
    parser.add_argument("--wait-state-interval", type=float, default=0.05)
    parser.add_argument(
        "--vga-sequence-frames",
        type=int,
        default=0,
        help="After the final halt, continue and sample this many raw VGA frames.",
    )
    parser.add_argument(
        "--vga-sequence-interval",
        type=float,
        default=1.0 / 70.0,
        help="Wall-clock interval between VGA sequence samples.",
    )
    parser.add_argument(
        "--vga-sequence-stop-sha256",
        default="",
        help="Halt the sequence after capturing a VGA frame with this SHA-256 hash.",
    )
    parser.add_argument(
        "--vga-sequence-screenshot-on-stop",
        action="store_true",
        help=(
            "Capture one running screenshot only when the VGA sequence "
            "matches --vga-sequence-stop-sha256."
        ),
    )
    parser.add_argument(
        "--vga-sequence-screenshot-all",
        action="store_true",
        help="Capture a running QMP screenshot for every VGA sequence sample.",
    )
    parser.add_argument(
        "--display-sequence-frames",
        type=int,
        default=0,
        help=(
            "After the final halt, continue and sample this many completed "
            "renderer source frames with matching DAC state."
        ),
    )
    parser.add_argument(
        "--display-sequence-interval",
        type=float,
        default=1.0 / 70.0,
        help="Wall-clock interval between completed display samples.",
    )
    parser.add_argument("--dump-segment", choices=["ds", "ss"], default="ss")
    parser.add_argument("--dump-size", type=lambda s: int(s, 0), default=0x4e00)
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument(
        "--input-script",
        type=Path,
        help=(
            "Versioned state-boundary input script used by "
            "checkpointstatescriptfile."
        ),
    )
    parser.add_argument(
        "--state-input-stop-value",
        help=(
            "Ask the state-input backend to request a debugger stop at this "
            "unwrapped state value."
        ),
    )
    args = parser.parse_args()
    if not 0 <= args.post_resume_display_history_capacity <= 64:
        parser.error(
            "--post-resume-display-history-capacity must be in 0..64"
        )
    try:
        checkpoint_screenshot_preserve_memory = [
            parse_memory_region(spec)
            for spec in args.checkpoint_screenshot_preserve_memory
        ]
    except ValueError as exc:
        parser.error(
            f"invalid --checkpoint-screenshot-preserve-memory: {exc}"
        )
    if checkpoint_screenshot_preserve_memory and not args.checkpoint_screenshot:
        parser.error(
            "--checkpoint-screenshot-preserve-memory requires "
            "--checkpoint-screenshot"
        )
    post_display_break = (
        parse_segmented_address(args.checkpoint_post_display_break_segmented)
        if args.checkpoint_post_display_break_segmented
        else None
    )
    post_display_poke: tuple[int, bytes] | None = None
    if args.checkpoint_post_display_poke:
        poke_parts = args.checkpoint_post_display_poke.split(":", 1)
        if len(poke_parts) != 2:
            parser.error("--checkpoint-post-display-poke requires ADDRESS:HEX")
        post_display_poke = (int(poke_parts[0], 0), bytes.fromhex(poke_parts[1]))
        if not post_display_poke[1]:
            parser.error("--checkpoint-post-display-poke bytes must not be empty")
    if (post_display_break is None) != (post_display_poke is None):
        parser.error(
            "--checkpoint-post-display-break-segmented and "
            "--checkpoint-post-display-poke must be supplied together"
        )
    if args.checkpoint_post_display_delay <= 0:
        parser.error("--checkpoint-post-display-delay must be positive")
    final_post_display_break = (
        parse_segmented_address(args.final_post_display_break_segmented)
        if args.final_post_display_break_segmented
        else None
    )
    final_post_display_poke: tuple[int, bytes] | None = None
    if args.final_post_display_poke:
        poke_parts = args.final_post_display_poke.split(":", 1)
        if len(poke_parts) != 2:
            parser.error("--final-post-display-poke requires ADDRESS:HEX")
        try:
            final_post_display_poke = (
                int(poke_parts[0], 0),
                bytes.fromhex(poke_parts[1]),
            )
        except ValueError as exc:
            parser.error(f"invalid --final-post-display-poke: {exc}")
        if not final_post_display_poke[1]:
            parser.error("--final-post-display-poke bytes must not be empty")
    if (final_post_display_break is None) != (final_post_display_poke is None):
        parser.error(
            "--final-post-display-break-segmented and "
            "--final-post-display-poke must be supplied together"
        )
    if args.final_post_display_delay <= 0:
        parser.error("--final-post-display-delay must be positive")
    state_post_display_break = (
        post_display_break
        if checkpoint_post_display_enabled(
            args.checkpoint_post_display_scope, "state"
        )
        else None
    )
    state_post_display_poke = (
        post_display_poke if state_post_display_break is not None else None
    )
    if (
        args.vga_sequence_screenshot_on_stop
        and not args.vga_sequence_stop_sha256
    ):
        parser.error(
            "--vga-sequence-screenshot-on-stop requires "
            "--vga-sequence-stop-sha256"
        )
    post_resume_break_hit_series = (
        parse_breakpoint_hit_series(args.post_resume_break_hit_series)
        if args.post_resume_break_hit_series is not None
        else None
    )
    post_resume_break_segmented = (
        parse_segmented_address(args.post_resume_break_segmented)
        if args.post_resume_break_segmented is not None
        else None
    )
    post_resume_next_break_segmented = (
        parse_segmented_address(args.post_resume_next_break_segmented)
        if args.post_resume_next_break_segmented is not None
        else None
    )
    post_resume_next_break_hit_series = (
        parse_breakpoint_hit_series(
            args.post_resume_next_break_hit_series
        )
        if args.post_resume_next_break_hit_series is not None
        else None
    )
    call_near_break_segmented = (
        parse_segmented_address(args.call_near_break_segmented)
        if args.call_near_break_segmented is not None
        else None
    )
    state_side_break_segmented = (
        parse_segmented_address(args.state_side_break_segmented)
        if args.state_side_break_segmented is not None
        else None
    )
    state_side_break_max_hits = (
        args.state_side_break_max_hits
        if args.state_side_break_max_hits > 0
        else None
    )
    if args.state_side_break_max_hits < 0:
        parser.error("--state-side-break-max-hits must be non-negative")
    if args.state_side_break_start_value < 0:
        parser.error("--state-side-break-start-value must be non-negative")
    if args.state_side_break_poke and state_side_break_segmented is None:
        parser.error(
            "--state-side-break-poke requires --state-side-break-segmented"
        )
    state_side_break_start_value = (
        args.state_side_break_start_value
        if args.state_side_break_start_value > 0
        else None
    )
    wait_predicates = [parse_state_predicate(spec) for spec in args.wait_state]
    state_fields = load_schema(args.state_schema) if args.state_schema else []
    state_input_metadata: dict[str, str] = {}
    state_input_events: list[tuple[int, bool, list[str]]] = []
    if args.input_script is not None:
        state_input_metadata, state_input_events = load_state_input_script(
            args.input_script
        )
    screen_classifier = (
        ScreenClassifier.load(args.screen_signatures)
        if args.screen_signatures
        else None
    )
    load_save_state_metadata: dict[str, Any] | None = None
    if wait_predicates and not state_fields:
        parser.error("--wait-state requires --state-schema")
    try:
        save_state_target = checkpoint_save_state_target(
            args.checkpoint_save_state,
            args.startup_key,
            args.resume_checkpoint_script,
            (
                args.post_resume_next_break_linear is not None
                or post_resume_next_break_segmented is not None
            ),
            getattr(args, "state_input_stop_value", None),
            getattr(args, "load_save_state_continue", False),
            args.checkpoint_save_state_first,
        )
    except ValueError as exc:
        parser.error(str(exc))
    if args.load_save_state is not None:
        if not args.load_save_state.is_file():
            parser.error(
                f"--load-save-state does not exist: {args.load_save_state}"
            )
        # A loaded full-state run is already at its guest boundary.  Permit
        # only timing/capture controls here; keyboard and debugger setup still
        # belong in the resume/post-restore paths so the restored state cannot
        # be perturbed before the caller explicitly resumes it.
        load_safe_startup_prefixes = (
            "runfor:",
            "wait:",
            "capture-wave:",
            # A breakpoint series only installs debugger boundaries and does
            # not mutate the restored guest.  Permit it as a safe post-load
            # acceleration path for long deterministic routes.
            "breakseries:",
        )
        if args.startup_key and not all(
            key.startswith(load_safe_startup_prefixes)
            for key in args.startup_key
        ):
            parser.error(
                "--load-save-state only supports runfor, wait, and "
                "capture-wave startup actions; use resume or post-restore "
                "actions for keyboard/setup work"
            )
        try:
            load_save_state_metadata = (
                load_save_state_checkpoint_metadata(args.load_save_state)
            )
        except ValueError as exc:
            parser.error(str(exc))
    elif args.load_save_state_paused:
        parser.error("--load-save-state-paused requires --load-save-state")
    elif args.load_save_state_continue:
        parser.error(
            "--load-save-state-continue requires --load-save-state"
        )
    if args.load_save_state_continue and args.resume_checkpoint_script:
        parser.error(
            "--load-save-state-continue cannot be combined with "
            "--resume-checkpoint-script"
        )
    # A paused full-state load can be edited at its exact boundary before the
    # guest is released.  Defer the existing continue mode until after those
    # edits; this avoids executing a few uncontrolled instructions while the
    # RSP/QMP clients attach and makes the mode useful for deterministic
    # substitution probes.
    defer_loaded_state_continue = bool(
        args.load_save_state is not None
        and args.load_save_state_paused
        and args.load_save_state_continue
        and (args.poke or args.poke_file)
    )
    defer_loaded_state_resume = bool(
        args.load_save_state is not None
        and args.load_save_state_paused
        and args.resume_checkpoint_script
    )
    defer_loaded_state_release = should_defer_paused_load_release(
        paused=args.load_save_state_paused,
        continue_after_load=args.load_save_state_continue,
        has_edits=bool(args.poke or args.poke_file),
        has_resume_checkpoint=bool(args.resume_checkpoint_script),
    )
    if defer_loaded_state_continue and (
        args.halt_after_poke
        or args.call_near is not None
        or args.resume_checkpoint_script
    ):
        parser.error(
            "paused load continue-after-poke cannot be combined with "
            "halt-after-poke, call-near, or a resume checkpoint"
        )
    if args.load_save_state_ready_screen is not None:
        if args.load_save_state is None:
            parser.error(
                "--load-save-state-ready-screen requires --load-save-state"
            )
        if screen_classifier is None:
            parser.error(
                "--load-save-state-ready-screen requires "
                "--screen-signatures"
            )
        if args.load_save_state_ready_timeout <= 0:
            parser.error(
                "--load-save-state-ready-timeout must be positive"
            )
    if args.resume_checkpoint_script:
        if (
            args.resume_checkpoint_script.startswith(
                "checkpointstatescriptfile:"
            )
            and args.input_script is None
        ):
            parser.error(
                "checkpointstatescriptfile resume requires --input-script"
            )
        if not state_fields:
            parser.error(
                "--resume-checkpoint-script requires --state-schema"
            )
        if (
            args.resume_script_event_owner == "backend"
            and not args.resume_checkpoint_script.startswith(
                "checkpointstatescriptfile:"
            )
        ):
            parser.error(
                "backend resume script event ownership requires "
                "checkpointstatescriptfile"
            )
        if args.resume_next_linear is None:
            parser.error(
                "--resume-checkpoint-script requires --resume-next-linear"
            )
        if args.halt_after_poke:
            parser.error(
                "--resume-checkpoint-script cannot be combined with "
                "--halt-after-poke"
            )
    if (
        (
            args.post_resume_break_linear is not None
            or post_resume_break_segmented is not None
        )
        and not args.resume_checkpoint_script
        and args.state_input_stop_value is None
    ):
        parser.error(
            "post-resume breakpoints require "
            "--resume-checkpoint-script or --state-input-stop-value"
        )
    if args.call_near_continue_after_return and args.call_near is None:
        parser.error(
            "--call-near-continue-after-return requires --call-near"
        )
    if args.call_near_break_linear is not None and args.call_near is None:
        parser.error("--call-near-break-linear requires --call-near")
    if args.call_near_break_segmented is not None and args.call_near is None:
        parser.error("--call-near-break-segmented requires --call-near")
    if args.call_near_break_offset is not None and args.call_near is None:
        parser.error("--call-near-break-offset requires --call-near")
    if args.call_near_break_offset is not None and not (
        0 <= args.call_near_break_offset <= 0xFFFF
    ):
        parser.error("--call-near-break-offset must be a 16-bit offset")
    if (
        args.call_near_break_linear is not None
        and (
            args.call_near_break_segmented is not None
            or args.call_near_break_offset is not None
        )
    ):
        parser.error(
            "call-near interior breakpoint address forms are mutually "
            "exclusive"
        )
    if (
        args.call_near_break_segmented is not None
        and args.call_near_break_offset is not None
    ):
        parser.error(
            "--call-near-break-segmented and --call-near-break-offset "
            "are mutually exclusive"
        )
    if (
        (
            args.call_near_break_linear is not None
            or args.call_near_break_segmented is not None
            or args.call_near_break_offset is not None
        )
        and args.call_near_continue_after_return
    ):
        parser.error(
            "--call-near-break-linear cannot be combined with "
            "--call-near-continue-after-return"
        )
    if args.call_near_continue_after_return and (
        args.halt_after_poke or args.resume_checkpoint_script
    ):
        parser.error(
            "--call-near-continue-after-return cannot be combined with "
            "--halt-after-poke or --resume-checkpoint-script"
        )
    if post_resume_break_hit_series is not None and (
        args.post_resume_break_linear is None
        and post_resume_break_segmented is None
    ):
        parser.error(
            "--post-resume-break-hit-series requires a first "
            "post-resume breakpoint"
        )
    if (
        args.post_resume_break_linear is not None
        and post_resume_break_segmented is not None
    ):
        parser.error(
            "--post-resume-break-linear and "
            "--post-resume-break-segmented are mutually exclusive"
        )
    if args.post_resume_break_hit_count < 1:
        parser.error("--post-resume-break-hit-count must be positive")
    if (
        args.post_resume_next_break_linear is not None
        and post_resume_next_break_segmented is not None
    ):
        parser.error(
            "--post-resume-next-break-linear and "
            "--post-resume-next-break-segmented are mutually exclusive"
        )
    has_post_resume_next_break = (
        args.post_resume_next_break_linear is not None
        or post_resume_next_break_segmented is not None
    )
    if args.checkpoint_save_state_first and not args.checkpoint_save_state:
        parser.error(
            "--checkpoint-save-state-first requires --checkpoint-save-state"
        )
    if args.checkpoint_save_state_first and has_post_resume_next_break:
        parser.error(
            "--checkpoint-save-state-first cannot be combined with a "
            "post-resume next breakpoint"
        )
    has_post_resume_pokes = bool(
        args.post_resume_poke or args.post_resume_poke_file
    )
    has_post_resume_break = (
        args.post_resume_break_linear is not None
        or post_resume_break_segmented is not None
    )
    direct_resume_final_poke = (
        has_post_resume_pokes
        and has_post_resume_break
        and not has_post_resume_next_break
        and not args.post_resume_continue_after_poke
        and not args.checkpoint_save_state_first
    )
    if has_post_resume_pokes and not (
        has_post_resume_next_break
        or args.post_resume_continue_after_poke
        or args.checkpoint_save_state_first
        or direct_resume_final_poke
    ):
        parser.error(
            "--post-resume-poke/--post-resume-poke-file requires "
            "--post-resume-next-break-linear, "
            "--post-resume-next-break-segmented, or "
            "--post-resume-continue-after-poke, or "
            "--checkpoint-save-state-first, or a first "
            "--post-resume-break-* for a final-checkpoint poke"
        )
    if (
        (args.post_resume_continue_after_poke or args.post_resume_continue)
        and has_post_resume_next_break
    ):
        parser.error(
            "post-resume continuation cannot be combined with "
            "--post-resume-next-break-*"
        )
    if (
        args.post_resume_continue_after_poke
        and not has_post_resume_pokes
    ):
        parser.error(
            "--post-resume-continue-after-poke requires "
            "--post-resume-poke or --post-resume-poke-file"
        )
    if args.post_resume_continue and not has_post_resume_break:
        parser.error(
            "--post-resume-continue requires a first "
            "--post-resume-break-*"
        )
    if args.post_resume_continue and has_post_resume_pokes:
        parser.error(
            "--post-resume-continue is non-mutating and cannot be combined "
            "with --post-resume-poke/--post-resume-poke-file"
        )
    if has_post_resume_pokes and (
        args.post_resume_break_linear is None
        and post_resume_break_segmented is None
    ):
        parser.error(
            "--post-resume-poke/--post-resume-poke-file requires a first "
            "--post-resume-break-*"
        )
    if has_post_resume_next_break and (
        args.post_resume_break_linear is None
        and post_resume_break_segmented is None
    ):
        parser.error(
            "--post-resume-next-break-* requires a first "
            "--post-resume-break-*"
        )
    if args.post_resume_next_break_hit_count < 1:
        parser.error(
            "--post-resume-next-break-hit-count must be positive"
        )
    if (
        post_resume_next_break_hit_series is not None
        and not has_post_resume_next_break
    ):
        parser.error(
            "--post-resume-next-break-hit-series requires a "
            "post-resume next breakpoint"
        )
    if (
        post_resume_next_break_hit_series is not None
        and args.checkpoint_save_state
    ):
        parser.error(
            "--post-resume-next-break-hit-series cannot be combined with "
            "--checkpoint-save-state"
        )
    if post_resume_break_hit_series is not None and (
        has_post_resume_next_break
        or has_post_resume_pokes
        or args.post_resume_continue_after_poke
        or args.post_resume_continue
    ):
        parser.error(
            "--post-resume-break-hit-series cannot be combined with "
            "post-resume poke files or a next breakpoint"
        )
    if args.vga_width <= 0 or args.vga_height <= 0:
        parser.error("--vga-width and --vga-height must be positive")
    if screen_classifier and (
        screen_classifier.width != args.vga_width
        or screen_classifier.height != args.vga_height
    ):
        parser.error(
            "--screen-signatures dimensions must match --vga-width/--vga-height"
        )
    vga_size = args.vga_width * args.vga_height
    pgm_header = f"P5\n{args.vga_width} {args.vga_height}\n255\n".encode("ascii")

    def classify_frame(raw: bytes) -> str:
        if screen_classifier is None:
            raise RuntimeError(
                "VGA state actions require --screen-signatures"
            )
        return screen_classifier.classify(raw)

    qmp_load: QmpClient | None = None
    if args.load_save_state is not None:
        qmp_load = QmpClient(args.host, args.qmp_port, args.timeout)
        try:
            if args.load_save_state_ready_screen is not None:
                wait_for_qmp_screen(
                    qmp_load,
                    screen_classifier,
                    args.vga_address,
                    vga_size,
                    args.load_save_state_ready_screen,
                    args.load_save_state_ready_timeout,
                    args.wait_state_interval,
                )
            if args.load_save_state_paused:
                if not qmp_load.supports_loadstate_paused:
                    raise RuntimeError(
                        "--load-save-state-paused requires a backend with "
                        "QMP loadstate-paused support"
                    )
                qmp_load.load_state_paused(args.load_save_state)
            else:
                qmp_load.load_state(args.load_save_state)
                qmp_load.close()
                qmp_load = None
        except BaseException:
            qmp_load.close()
            qmp_load = None
            raise

    gdb = RspClient(args.host, args.gdb_port, args.timeout)
    # QMP is the preferred bulk-memory path.  Keep RSP as a fallback for
    # checkpoints because a halted late DOSBox-X guest can stop answering a
    # QMP memdump while its GDB stub remains responsive.
    QmpClient.set_memory_fallback(gdb.read_memory_chunked)
    wave_capture_active = False
    try:
        halted_stop: str | None = None
        halted_regs: dict[str, int] | None = None
        wait_state_match: dict[str, Any] | None = None
        break_state_match: dict[str, Any] | None = None
        state_checkpoints: list[dict[str, Any]] = []
        state_side_breakpoint_records: list[dict[str, Any]] = []
        active_breakpoint_linear: int | None = None
        initial = gdb.packet("?")
        if initial.startswith(("S", "T")):
            if qmp_load is not None and not defer_loaded_state_release:
                # A paused QMP load is already an exact debugger boundary.
                # Keep it held unless the caller explicitly requested
                # load-save-state-continue; otherwise the old unconditional
                # ``cont`` advanced the guest before a supposedly halted
                # dump or breakpoint could inspect it.
                if not (
                    args.load_save_state_paused
                    and not args.load_save_state_continue
                ):
                    qmp_load.command("cont")
                qmp_load.close()
                qmp_load = None
            # The remotedebug fork starts halted when a GDB client is attached.
            if args.break_linear is not None and not defer_loaded_state_release:
                gdb.insert_breakpoint(args.break_linear)
                active_breakpoint_linear = args.break_linear
                print(
                    f"inserted linear breakpoint at 0x{args.break_linear:05x}",
                    flush=True,
                )
            if args.load_save_state is not None:
                if args.load_save_state_continue and not defer_loaded_state_continue:
                    # A loaded state is initially halted so callers can set
                    # up a resume/debug boundary.  When a logical wait-state
                    # owns the next boundary, leave the guest running for
                    # that poller instead of waiting for a debugger/backend
                    # stop that may not exist.  This also avoids requiring a
                    # state-input backend stop for a plain loaded-state wait.
                    if wait_predicates:
                        halted_stop = None
                        halted_regs = None
                        print(
                            "loaded full state for wait-state polling",
                            flush=True,
                        )
                    else:
                        gdb.continue_nowait()
                        halted_stop = gdb.wait_for_stop(args.timeout)
                        halted_regs = gdb.registers()
                        print(
                            "continued loaded full state to backend capture "
                            f"boundary: {halted_stop}",
                            flush=True,
                        )
                else:
                    halted_stop = initial
                    halted_regs = gdb.registers()
                    if defer_loaded_state_continue and args.break_linear is not None:
                        gdb.insert_breakpoint(args.break_linear)
                        active_breakpoint_linear = args.break_linear
                        print(
                            "inserted linear breakpoint after paused state load "
                            f"at 0x{args.break_linear:05x}",
                            flush=True,
                        )
            else:
                gdb.continue_nowait()

        args.out_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_screenshot_baseline = set(args.out_dir.glob("*.png"))
        (args.out_dir / "remote_runtime_args.json").write_text(
            json.dumps(
                {
                    "startup_key": args.startup_key,
                    "post_restore_key": args.post_restore_key,
                    "wait_state": args.wait_state,
                    "post_wait_key": args.post_wait_key,
                    "vga_sequence_frames": args.vga_sequence_frames,
                    "vga_sequence_interval": args.vga_sequence_interval,
                    "display_sequence_frames": args.display_sequence_frames,
                    "display_sequence_interval": args.display_sequence_interval,
                    "vga_sequence_memory_segment": (
                        args.dump_segment if args.dump_size > 0 else None
                    ),
                    "vga_sequence_memory_size": (
                        args.dump_size if args.dump_size > 0 else 0
                    ),
                    "vga_sequence_screenshot_all": (
                        args.vga_sequence_screenshot_all
                    ),
                    "omit_checkpoint_vga": args.omit_checkpoint_vga,
                    "checkpoint_dac": args.checkpoint_dac,
                    "checkpoint_displaydump": args.checkpoint_displaydump,
                    "checkpoint_screenshot": args.checkpoint_screenshot,
                    "checkpoint_screenshot_preserve_memory": [
                        {"address": address, "size": size}
                        for address, size in (
                            checkpoint_screenshot_preserve_memory
                        )
                    ],
                    "checkpoint_save_state": args.checkpoint_save_state,
                    "checkpoint_save_state_first": (
                        args.checkpoint_save_state_first
                    ),
                    "save_state_target": save_state_target,
                    "state_input_stop_value": getattr(
                        args, "state_input_stop_value", None
                    ),
                    "load_save_state": (
                        {
                            "path": str(args.load_save_state),
                            "paused_load": args.load_save_state_paused,
                            "size": args.load_save_state.stat().st_size,
                            "sha256": sha256_file(args.load_save_state),
                            "ready_screen": (
                                args.load_save_state_ready_screen
                            ),
                            "ready_timeout": (
                                args.load_save_state_ready_timeout
                            ),
                            "checkpoint_metadata": (
                                str(
                                    args.load_save_state.with_name(
                                        "remote_runtime_registers.json"
                                    )
                                )
                            ),
                            "dump_segment_value": (
                                load_save_state_metadata[
                                    "dump_segment_value"
                                ]
                            ),
                        }
                        if args.load_save_state is not None
                        else None
                    ),
                    "break_linear": args.break_linear,
                    **interrupted_probe_manifest(args),
                    "restore_registers": (
                        str(args.restore_registers)
                        if args.restore_registers is not None
                        else None
                    ),
                    "resume_checkpoint_script": (
                        args.resume_checkpoint_script
                    ),
                    "resume_script_event_owner": (
                        args.resume_script_event_owner
                    ),
                    "post_resume_break_linear": (
                        args.post_resume_break_linear
                    ),
                    "post_resume_break_segmented": (
                        args.post_resume_break_segmented
                    ),
                    "post_resume_break_hit_count": (
                        args.post_resume_break_hit_count
                    ),
                    "post_resume_next_break_linear": (
                        args.post_resume_next_break_linear
                    ),
                    "post_resume_next_break_segmented": (
                        args.post_resume_next_break_segmented
                    ),
                    "post_resume_next_break_hit_count": (
                        args.post_resume_next_break_hit_count
                    ),
                    "post_resume_next_break_hit_series": (
                        post_resume_next_break_hit_series
                    ),
                    "post_resume_poke": args.post_resume_poke,
                    "post_resume_poke_file": args.post_resume_poke_file,
                    "post_resume_poke_at_final_checkpoint": (
                        direct_resume_final_poke
                    ),
                    "post_resume_continue_after_poke": (
                        args.post_resume_continue_after_poke
                    ),
                    "post_resume_continue": args.post_resume_continue,
                    "resume_next_linear": args.resume_next_linear,
                    "state_side_break_segmented": (
                        args.state_side_break_segmented
                    ),
                    "state_side_break_max_hits": (
                        args.state_side_break_max_hits
                    ),
                    "state_side_break_start_value": (
                        args.state_side_break_start_value
                    ),
                    "state_side_break_poke": args.state_side_break_poke,
                    "input_script": (
                        {
                            "path": str(args.input_script),
                            "sha256": hashlib.sha256(
                                args.input_script.read_bytes()
                            ).hexdigest(),
                            "metadata": state_input_metadata,
                            "event_count": len(state_input_events),
                        }
                        if args.input_script is not None
                        else None
                    ),
                    "initial_stop": initial,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        print(f"initial stop: {initial}", flush=True)
        if args.startup_key:
            time.sleep(args.startup_delay)
            qmp_startup = QmpClient(args.host, args.qmp_port, args.timeout)
            try:
                for key in args.startup_key:
                    if key.startswith("wait:"):
                        time.sleep(float(key.split(":", 1)[1]))
                        continue
                    if key.startswith("runfor:"):
                        seconds = parse_run_for_action(key)
                        gdb.continue_nowait()
                        time.sleep(seconds)
                        halted_stop = gdb.halt(args.timeout)
                        halted_regs = gdb.registers()
                        print(
                            f"ran guest for {seconds:.3f}s and re-halted: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("runtap:"):
                        qcode, hold_seconds = parse_run_tap_action(key)
                        gdb.continue_nowait()
                        qmp_startup.key_hold(qcode, hold_seconds)
                        halted_stop = gdb.halt(args.timeout)
                        halted_regs = gdb.registers()
                        print(
                            f"ran guest with key tap {qcode} "
                            f"{hold_seconds:.3f}s and re-halted: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("rununtilstop:"):
                        timeout = parse_run_until_stop_action(key)
                        gdb.continue_nowait()
                        halted_stop = gdb.wait_for_stop(timeout)
                        halted_regs = gdb.registers()
                        print(
                            "ran guest until debugger/backend stop "
                            f"(timeout {timeout:.3f}s): {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("tap:"):
                        parts = key.split(":")
                        if len(parts) not in {2, 3}:
                            raise ValueError(f"tap syntax: tap:<qcode>[:seconds], got {key!r}")
                        qcode = parts[1]
                        hold_seconds = float(parts[2]) if len(parts) == 3 else 0.2
                        qmp_startup.key_hold(qcode, hold_seconds)
                        print(f"key tap {qcode} {hold_seconds:.3f}s", flush=True)
                        time.sleep(0.15)
                        continue
                    if key.startswith("hold:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(f"hold syntax: hold:<qcode>:<seconds>, got {key!r}")
                        qcode = parts[1]
                        hold_seconds = float(parts[2])
                        qmp_startup.key_hold(qcode, hold_seconds)
                        print(f"key hold {qcode} {hold_seconds:.3f}s", flush=True)
                        time.sleep(0.15)
                        continue
                    if key.startswith("chord:"):
                        parts = key.split(":")
                        if len(parts) not in {2, 3}:
                            raise ValueError(
                                "chord syntax: chord:<qcode>+<qcode>[:seconds], "
                                f"got {key!r}"
                            )
                        qcodes = [qcode for qcode in parts[1].split("+") if qcode]
                        hold_seconds = float(parts[2]) if len(parts) == 3 else 0.15
                        qmp_startup.key_chord(qcodes, hold_seconds)
                        print(
                            f"key chord {'+'.join(qcodes)} {hold_seconds:.3f}s",
                            flush=True,
                        )
                        time.sleep(0.15)
                        continue
                    if key.startswith("break:"):
                        linear_address = int(key.split(":", 1)[1], 0)
                        stop = install_running_breakpoint(
                            gdb, linear_address, args.timeout
                        )
                        print(
                            f"breakpoint setup stop {stop}; "
                            f"inserted at 0x{linear_address:05x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breaknth:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(
                                "breaknth action syntax: "
                                "breaknth:<linear-address>:<positive-hit-count>"
                            )
                        linear_address = int(parts[1], 0)
                        hit_count = int(parts[2], 0)
                        halted_stop = stop_on_nth_breakpoint(
                            gdb,
                            linear_address,
                            hit_count,
                            args.timeout,
                        )
                        halted_regs = gdb.registers()
                        print(
                            f"stopped on breakpoint hit {hit_count} at "
                            f"0x{linear_address:05x}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breakstate:"):
                        (
                            linear_address,
                            predicate,
                            max_hits,
                        ) = parse_state_breakpoint_action(key)
                        if not state_fields:
                            raise ValueError(
                                "breakstate action requires --state-schema "
                                "with at least one field"
                            )
                        field_name = predicate[0]
                        if field_name not in {
                            field.name for field in state_fields
                        }:
                            raise ValueError(
                                "breakstate predicate references unknown "
                                f"schema field {field_name!r}"
                            )

                        def read_break_state(
                            registers: dict[str, int],
                        ) -> dict[str, int]:
                            segment = (
                                registers[args.dump_segment] & 0xFFFF
                            )
                            return read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            )

                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_breakpoint(
                            gdb,
                            linear_address,
                            predicate,
                            max_hits,
                            args.timeout,
                            read_break_state,
                        )
                        break_state_match = {
                            "linear_address": linear_address,
                            "predicate": format_state_predicates(
                                [predicate]
                            ),
                            "maximum_hits": max_hits,
                            "matched_hit": hit_index,
                            "state": matched_state,
                        }
                        print(
                            "stopped on state breakpoint hit "
                            f"{hit_index} at 0x{linear_address:05x}; "
                            f"{format_state_predicates([predicate])}: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith(
                        ("checkpointstatescript:", "checkpointstatescriptfile:")
                    ):
                        input_script_source = "inline"
                        input_script_metadata: dict[str, str] = {}
                        if key.startswith("checkpointstatescriptfile:"):
                            (
                                linear_address,
                                field_name,
                                values,
                                max_hits,
                            ) = parse_state_checkpoint_script_file_action(key)
                            if args.input_script is None:
                                raise ValueError(
                                    "checkpointstatescriptfile action "
                                    "requires --input-script"
                                )
                            input_events = state_input_events
                            input_script_metadata = state_input_metadata
                            input_script_source = str(args.input_script)
                            configured_field = input_script_metadata.get(
                                "state_field"
                            )
                            if (
                                configured_field is not None
                                and configured_field != field_name
                            ):
                                raise ValueError(
                                    "state input script field "
                                    f"{configured_field!r} does not match "
                                    f"action field {field_name!r}"
                                )
                        else:
                            (
                                linear_address,
                                field_name,
                                values,
                                max_hits,
                                input_events,
                            ) = parse_state_checkpoint_script_action(key)
                        observed_values = merged_state_script_values(
                            values,
                            input_events,
                        )
                        captured_values = set(values)
                        if not state_fields:
                            raise ValueError(
                                "checkpointstatescript action requires "
                                "--state-schema with at least one field"
                            )
                        if field_name not in {
                            field.name for field in state_fields
                        }:
                            raise ValueError(
                                "checkpointstatescript references unknown "
                                f"schema field {field_name!r}"
                            )

                        def read_script_checkpoint_state(
                            registers: dict[str, int],
                        ) -> dict[str, int]:
                            segment = (
                                registers[args.dump_segment] & 0xFFFF
                            )
                            return read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            )

                        def capture_script_checkpoint(
                            value: int,
                            stop: str,
                            registers: dict[str, int],
                            state: dict[str, int],
                            hit_index: int,
                        ) -> None:
                            if value not in captured_values:
                                return
                            record = write_state_checkpoint(
                                qmp_startup,
                                args.out_dir / "checkpoints",
                                field_name,
                                value,
                                stop,
                                registers,
                                state,
                                hit_index,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=args.checkpoint_dac,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=args.checkpoint_screenshot,
                            )
                            capture_configured_post_display(
                                gdb,
                                qmp_startup,
                                args.timeout,
                                state_post_display_break,
                                state_post_display_poke,
                                record,
                                linear_address,
                                args.checkpoint_post_display_delay,
                            )
                            state_checkpoints.append(record)
                            print(
                                "captured state checkpoint "
                                f"{field_name}={value} on hit {hit_index}",
                                flush=True,
                            )

                        def transition_script_keys(value: int) -> None:
                            for (
                                event_value,
                                pressed,
                                qcodes,
                            ) in input_events:
                                if event_value != value:
                                    continue
                                ordered_qcodes = (
                                    qcodes if pressed else list(reversed(qcodes))
                                )
                                for qcode in ordered_qcodes:
                                    qmp_startup.key_event(qcode, pressed)
                                print(
                                    f"key {'down' if pressed else 'up'} "
                                    f"{'+'.join(qcodes)} at "
                                    f"{field_name}={value}",
                                    flush=True,
                                )

                        def capture_script_side_breakpoint(
                            side_hit: int,
                            side_stop: str,
                            side_registers: dict[str, int],
                        ) -> None:
                            side_stack = breakpoint_stack_snapshot(
                                gdb,
                                side_registers,
                            )
                            side_writes = apply_halted_pokes(
                                gdb,
                                args.state_side_break_poke,
                                side_registers,
                            )
                            state_side_breakpoint_records.append(
                                {
                                    "hit": side_hit,
                                    "stop": side_stop,
                                    "registers": side_registers,
                                    "stack": side_stack,
                                    "writes": side_writes,
                                    "state": read_script_checkpoint_state(
                                        side_registers
                                    ),
                                }
                            )

                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_checkpoints(
                            gdb,
                            linear_address,
                            field_name,
                            observed_values,
                            max_hits,
                            args.timeout,
                            read_script_checkpoint_state,
                            capture_script_checkpoint,
                            transition_script_keys,
                            False,
                            (
                                pack_segment_offset(
                                    *state_side_break_segmented
                                ),
                                (state_side_break_segmented[0] << 4)
                                + state_side_break_segmented[1],
                            )
                            if state_side_break_segmented is not None
                            else None,
                            capture_script_side_breakpoint
                            if state_side_break_segmented is not None
                            else None,
                            state_side_break_max_hits,
                            state_side_break_start_value,
                        )
                        if args.checkpoint_save_state:
                            (
                                halted_stop,
                                halted_regs,
                            ) = finalize_halted_checkpoint_save_state(
                                qmp_startup,
                                gdb,
                                linear_address,
                                state_checkpoints[-1],
                                args.timeout,
                                lambda _registers, segment=(
                                    halted_regs[args.dump_segment] & 0xFFFF
                                ): read_segment_state(
                                    gdb,
                                    segment,
                                    state_fields,
                                ),
                            )
                        break_state_match = {
                            "linear_address": linear_address,
                            "predicate": f"{field_name}=={values[-1]}",
                            "maximum_hits": max_hits,
                            "matched_hit": hit_index,
                            "state": matched_state,
                            "input_script_source": input_script_source,
                            "input_script_metadata": input_script_metadata,
                            "input_script": [
                                {
                                    "value": value,
                                    "pressed": pressed,
                                    "qcodes": qcodes,
                                }
                                for value, pressed, qcodes in input_events
                            ],
                        }
                        print(
                            f"captured {len(values)} state checkpoints with "
                            f"{len(input_events)} input transitions at "
                            f"0x{linear_address:05x}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("checkpointstatehold:"):
                        (
                            linear_address,
                            field_name,
                            values,
                            max_hits,
                            qcode,
                            press_value,
                            release_value,
                        ) = parse_state_checkpoint_hold_action(key)
                        if not state_fields:
                            raise ValueError(
                                "checkpointstatehold action requires "
                                "--state-schema with at least one field"
                            )
                        if field_name not in {
                            field.name for field in state_fields
                        }:
                            raise ValueError(
                                "checkpointstatehold references unknown "
                                f"schema field {field_name!r}"
                            )

                        def read_hold_checkpoint_state(
                            registers: dict[str, int],
                        ) -> dict[str, int]:
                            segment = (
                                registers[args.dump_segment] & 0xFFFF
                            )
                            return read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            )

                        def capture_hold_checkpoint(
                            value: int,
                            stop: str,
                            registers: dict[str, int],
                            state: dict[str, int],
                            hit_index: int,
                        ) -> None:
                            record = write_state_checkpoint(
                                qmp_startup,
                                args.out_dir / "checkpoints",
                                field_name,
                                value,
                                stop,
                                registers,
                                state,
                                hit_index,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=args.checkpoint_dac,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=args.checkpoint_screenshot,
                            )
                            state_checkpoints.append(record)
                            print(
                                "captured state checkpoint "
                                f"{field_name}={value} on hit {hit_index}",
                                flush=True,
                            )

                        def transition_hold_key(value: int) -> None:
                            if value == press_value:
                                for held_qcode in qcode.split("+"):
                                    qmp_startup.key_event(held_qcode, True)
                                print(
                                    f"key down {qcode} at "
                                    f"{field_name}={value}",
                                    flush=True,
                                )
                            elif value == release_value:
                                for held_qcode in reversed(qcode.split("+")):
                                    qmp_startup.key_event(held_qcode, False)
                                print(
                                    f"key up {qcode} at "
                                    f"{field_name}={value}",
                                    flush=True,
                                )

                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_checkpoints(
                            gdb,
                            linear_address,
                            field_name,
                            values,
                            max_hits,
                            args.timeout,
                            read_hold_checkpoint_state,
                            capture_hold_checkpoint,
                            transition_hold_key,
                        )
                        if args.checkpoint_save_state:
                            (
                                halted_stop,
                                halted_regs,
                            ) = finalize_halted_checkpoint_save_state(
                                qmp_startup,
                                gdb,
                                linear_address,
                                state_checkpoints[-1],
                                args.timeout,
                                lambda _registers, segment=(
                                    halted_regs[args.dump_segment] & 0xFFFF
                                ): read_segment_state(
                                    gdb,
                                    segment,
                                    state_fields,
                                ),
                            )
                        break_state_match = {
                            "linear_address": linear_address,
                            "predicate": f"{field_name}=={values[-1]}",
                            "maximum_hits": max_hits,
                            "matched_hit": hit_index,
                            "state": matched_state,
                            "input_hold": {
                                "qcode": qcode,
                                "press_value": press_value,
                                "release_value": release_value,
                            },
                        }
                        print(
                            f"captured {len(values)} state checkpoints with "
                            f"{qcode} held from {press_value} through "
                            f"{release_value} at 0x{linear_address:05x}: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("checkpointstate:"):
                        (
                            linear_address,
                            field_name,
                            values,
                            max_hits,
                        ) = parse_state_checkpoint_action(key)
                        if not state_fields:
                            raise ValueError(
                                "checkpointstate action requires "
                                "--state-schema with at least one field"
                            )
                        if field_name not in {
                            field.name for field in state_fields
                        }:
                            raise ValueError(
                                "checkpointstate references unknown "
                                f"schema field {field_name!r}"
                            )

                        def read_checkpoint_state(
                            registers: dict[str, int],
                        ) -> dict[str, int]:
                            segment = (
                                registers[args.dump_segment] & 0xFFFF
                            )
                            return read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            )

                        def capture_checkpoint(
                            value: int,
                            stop: str,
                            registers: dict[str, int],
                            state: dict[str, int],
                            hit_index: int,
                        ) -> None:
                            record = write_state_checkpoint(
                                qmp_startup,
                                args.out_dir / "checkpoints",
                                field_name,
                                value,
                                stop,
                                registers,
                                state,
                                hit_index,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=args.checkpoint_dac,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=args.checkpoint_screenshot,
                            )
                            state_checkpoints.append(record)
                            print(
                                "captured state checkpoint "
                                f"{field_name}={value} on hit {hit_index}",
                                flush=True,
                            )

                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_checkpoints(
                            gdb,
                            linear_address,
                            field_name,
                            values,
                            max_hits,
                            args.timeout,
                            read_checkpoint_state,
                            capture_checkpoint,
                        )
                        if args.checkpoint_save_state:
                            (
                                halted_stop,
                                halted_regs,
                            ) = finalize_halted_checkpoint_save_state(
                                qmp_startup,
                                gdb,
                                linear_address,
                                state_checkpoints[-1],
                                args.timeout,
                                lambda _registers, segment=(
                                    halted_regs[args.dump_segment] & 0xFFFF
                                ): read_segment_state(
                                    gdb,
                                    segment,
                                    state_fields,
                                ),
                            )
                        break_state_match = {
                            "linear_address": linear_address,
                            "predicate": f"{field_name}=={values[-1]}",
                            "maximum_hits": max_hits,
                            "matched_hit": hit_index,
                            "state": matched_state,
                        }
                        print(
                            f"captured {len(values)} state checkpoints at "
                            f"0x{linear_address:05x}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breakstatesso:"):
                        (
                            backend_address,
                            predicate,
                            max_hits,
                        ) = parse_segmented_state_breakpoint_action(key)
                        if not state_fields:
                            raise ValueError(
                                "breakstatesso action requires "
                                "--state-schema with at least one field"
                            )
                        field_name = predicate[0]
                        if field_name not in {
                            field.name for field in state_fields
                        }:
                            raise ValueError(
                                "breakstatesso predicate references unknown "
                                f"schema field {field_name!r}"
                            )

                        def read_segmented_break_state(
                            registers: dict[str, int],
                        ) -> dict[str, int]:
                            segment = (
                                registers[args.dump_segment] & 0xFFFF
                            )
                            return read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            )

                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_breakpoint(
                            gdb,
                            backend_address,
                            predicate,
                            max_hits,
                            args.timeout,
                            read_segmented_break_state,
                        )
                        break_state_match = {
                            "backend_address": backend_address,
                            "predicate": format_state_predicates(
                                [predicate]
                            ),
                            "maximum_hits": max_hits,
                            "matched_hit": hit_index,
                            "state": matched_state,
                        }
                        print(
                            "stopped on segmented state breakpoint hit "
                            f"{hit_index}; "
                            f"{format_state_predicates([predicate])}: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("clearbreak:"):
                        parts = key.split(":")
                        if len(parts) != 2:
                            raise ValueError(
                                "clearbreak action syntax: "
                                "clearbreak:<linear-address>"
                            )
                        linear_address = int(parts[1], 0)
                        halted_stop = clear_halted_breakpoint(
                            gdb,
                            linear_address,
                            args.timeout,
                        )
                        halted_regs = gdb.registers()
                        print(
                            f"removed and stepped halted breakpoint at "
                            f"0x{linear_address:05x}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("removebreak:"):
                        parts = key.split(":")
                        if len(parts) != 2:
                            raise ValueError(
                                "removebreak action syntax: "
                                "removebreak:<linear-address>"
                            )
                        linear_address = int(parts[1], 0)
                        remove_halted_breakpoint(
                            gdb,
                            linear_address,
                        )
                        halted_regs = gdb.registers()
                        print(
                            f"removed halted breakpoint without stepping at "
                            f"0x{linear_address:05x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("removebreakso:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(
                                "removebreakso action syntax: "
                                "removebreakso:<segment>:<offset>"
                            )
                        segment = int(parts[1], 0)
                        offset = int(parts[2], 0)
                        backend_address = (
                            remove_halted_segmented_breakpoint(
                                gdb,
                                segment,
                                offset,
                            )
                        )
                        halted_regs = gdb.registers()
                        print(
                            "removed halted segmented breakpoint without "
                            f"stepping at {segment:04x}:{offset:04x} "
                            f"(backend 0x{backend_address:08x})",
                            flush=True,
                        )
                        continue
                    if key.startswith("breakwaithaltedso:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(
                                "breakwaithaltedso action syntax: "
                                "breakwaithaltedso:<segment>:<offset>"
                            )
                        segment = int(parts[1], 0)
                        offset = int(parts[2], 0)
                        (
                            halted_stop,
                            halted_regs,
                        ) = stop_on_halted_segmented_breakpoint(
                            gdb,
                            segment,
                            offset,
                            args.timeout,
                        )
                        print(
                            "stopped after resuming halted CPU toward "
                            f"{segment:04x}:{offset:04x}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("continuebreakso:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(
                                "continuebreakso action syntax: "
                                "continuebreakso:<segment>:<offset>"
                            )
                        segment = int(parts[1], 0)
                        offset = int(parts[2], 0)
                        backend_address = pack_segment_offset(
                            segment,
                            offset,
                        )
                        install_halted_breakpoint(
                            gdb,
                            backend_address,
                        )
                        halted_stop = None
                        halted_regs = None
                        print(
                            "resumed halted CPU toward breakpoint at "
                            f"{segment:04x}:{offset:04x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breakso:"):
                        parts = key.split(":")
                        if len(parts) != 3:
                            raise ValueError(
                                "breakso action syntax: "
                                "breakso:<segment>:<offset>"
                            )
                        segment = int(parts[1], 0)
                        offset = int(parts[2], 0)
                        backend_address = pack_segment_offset(
                            segment,
                            offset,
                        )
                        stop = install_running_breakpoint(
                            gdb,
                            backend_address,
                            args.timeout,
                        )
                        print(
                            f"breakpoint setup stop {stop}; inserted at "
                            f"{segment:04x}:{offset:04x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breaksonth:"):
                        backend_address, hit_count = (
                            parse_segmented_nth_breakpoint_action(key)
                        )
                        halted_stop = stop_on_nth_breakpoint(
                            gdb,
                            backend_address,
                            hit_count,
                            args.timeout,
                        )
                        halted_regs = gdb.registers()
                        print(
                            "stopped on segmented breakpoint hit "
                            f"{hit_count}: {halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("breakseries:"):
                        segment, offset, hit_counts = (
                            parse_segmented_breakpoint_series_action(key)
                        )
                        backend_address = pack_segment_offset(segment, offset)
                        expected_eip = (segment << 4) + offset
                        if halted_stop is None:
                            halted_stop = gdb.halt(args.timeout)
                            halted_regs = gdb.registers()
                        breakpoint_records: list[dict[str, Any]] = []

                        def capture_startup_breakpoint_hit(
                            series_hit: int,
                            series_stop: str,
                            series_registers: dict[str, int],
                        ) -> None:
                            record = write_state_checkpoint(
                                qmp_startup,
                                args.out_dir / "checkpoints",
                                "breakpoint_hit",
                                series_hit,
                                series_stop,
                                series_registers,
                                {"breakpoint_hit": series_hit},
                                series_hit,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=True,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=False,
                            )
                            if args.checkpoint_screenshot:
                                capture_halted_breakpoint_screenshot(
                                    gdb,
                                    qmp_startup,
                                    args.timeout,
                                    backend_address,
                                    expected_eip,
                                    args.vga_address,
                                    vga_size,
                                    record,
                                    args.checkpoint_post_display_delay,
                                    preserve_memory=(
                                        checkpoint_screenshot_preserve_memory
                                    ),
                                )
                            state_checkpoints.append(record)
                            breakpoint_records.append(record)
                            print(
                                "captured startup breakpoint hit "
                                f"{series_hit}",
                                flush=True,
                            )

                        (
                            halted_stop,
                            halted_regs,
                        ) = stop_on_post_resume_segmented_breakpoint_series(
                            gdb,
                            segment,
                            offset,
                            hit_counts,
                            args.timeout,
                            capture_startup_breakpoint_hit,
                        )
                        break_state_match = {
                            "startup_breakpoint_series": {
                                "segment": segment,
                                "offset": offset,
                                "hits": hit_counts,
                                "checkpoints": breakpoint_records,
                            }
                        }
                        print(
                            "captured startup breakpoint series "
                            f"{hit_counts} at {segment:04x}:{offset:04x}: "
                            f"{halted_stop}",
                            flush=True,
                        )
                        continue
                    if key.startswith("poke:"):
                        parts = key.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError(
                                "poke action syntax: "
                                "poke:<linear-address>:<hexbytes>"
                            )
                        linear_address = int(parts[1], 0)
                        data = bytes.fromhex(parts[2])
                        stop = apply_running_poke(
                            gdb,
                            linear_address,
                            data,
                            args.timeout,
                        )
                        print(
                            f"poke setup stop {stop}; wrote {len(data)} bytes "
                            f"at 0x{linear_address:05x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("pokehalted:"):
                        parts = key.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError(
                                "pokehalted action syntax: "
                                "pokehalted:<linear-address>:<hexbytes>"
                            )
                        linear_address = int(parts[1], 0)
                        data = bytes.fromhex(parts[2])
                        apply_halted_poke(
                            gdb,
                            linear_address,
                            data,
                        )
                        halted_stop = None
                        halted_regs = None
                        print(
                            f"resumed halted CPU after writing {len(data)} "
                            f"bytes at 0x{linear_address:05x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("writehalted:"):
                        parts = key.split(":", 2)
                        if len(parts) != 3:
                            raise ValueError(
                                "writehalted action syntax: "
                                "writehalted:<linear-address>:<hexbytes>"
                            )
                        linear_address = int(parts[1], 0)
                        data = bytes.fromhex(parts[2])
                        gdb.write_memory_chunked(linear_address, data)
                        halted_regs = gdb.registers()
                        print(
                            f"wrote {len(data)} halted bytes at "
                            f"0x{linear_address:05x}",
                            flush=True,
                        )
                        continue
                    if key.startswith("capture-wave:"):
                        operation = key.split(":", 1)[1]
                        if operation not in {"start", "stop"}:
                            raise ValueError(
                                "capture-wave syntax: capture-wave:start|stop, "
                                f"got {key!r}"
                            )
                        wave_capture_active = operation == "start"
                        qmp_startup.capture_wave(wave_capture_active)
                        print(f"capture wave {operation}", flush=True)
                        time.sleep(0.15)
                        continue
                    if key.startswith("keydown:"):
                        qcode = key.split(":", 1)[1]
                        qmp_startup.key_event(qcode, True)
                        print(f"key down {qcode}", flush=True)
                        time.sleep(0.15)
                        continue
                    if key.startswith("keyup:"):
                        qcode = key.split(":", 1)[1]
                        qmp_startup.key_event(qcode, False)
                        print(f"key up {qcode}", flush=True)
                        time.sleep(0.15)
                        continue
                    if key.startswith("waitvga:"):
                        state, timeout_s, poll_interval = (
                            parse_screen_wait_action(key, "waitvga")
                        )
                        deadline = time.time() + timeout_s
                        last_state = "unknown"
                        last_raw = b""
                        while time.time() < deadline:
                            last_raw = qmp_startup.memdump(args.vga_address, vga_size)
                            last_state = classify_frame(last_raw)
                            if last_state == state:
                                break
                            time.sleep(poll_interval)
                        else:
                            timeout_path = args.out_dir / f"waitvga_timeout_{state}.bin"
                            timeout_pgm_path = args.out_dir / f"waitvga_timeout_{state}.pgm"
                            timeout_path.write_bytes(last_raw)
                            timeout_pgm_path.write_bytes(pgm_header + last_raw)
                            raise RuntimeError(f"timed out waiting for VGA state {state!r}; last={last_state!r}")
                        print(f"waitvga matched {state}", flush=True)
                        continue
                    if key.startswith("waitnotvga:"):
                        state, timeout_s, poll_interval = (
                            parse_screen_wait_action(key, "waitnotvga")
                        )
                        deadline = time.time() + timeout_s
                        last_state = "unknown"
                        last_raw = b""
                        while time.time() < deadline:
                            last_raw = qmp_startup.memdump(args.vga_address, vga_size)
                            last_state = classify_frame(last_raw)
                            if last_state != state:
                                break
                            time.sleep(poll_interval)
                        else:
                            timeout_path = args.out_dir / f"waitnotvga_timeout_{state}.bin"
                            timeout_pgm_path = args.out_dir / f"waitnotvga_timeout_{state}.pgm"
                            timeout_path.write_bytes(last_raw)
                            timeout_pgm_path.write_bytes(pgm_header + last_raw)
                            raise RuntimeError(f"timed out waiting to leave VGA state {state!r}; last={last_state!r}")
                        print(f"waitnotvga left {state}; now {last_state}", flush=True)
                        continue
                    if key.startswith("drivevga:"):
                        parts = key.split(":")
                        if len(parts) not in {4, 5, 6}:
                            raise ValueError(
                                "drivevga syntax: drivevga:<state>:<timeout>:<qcode>[:hold][:interval], "
                                f"got {key!r}"
                            )
                        state = parts[1]
                        timeout_s = float(parts[2])
                        qcode = parts[3]
                        hold_seconds = float(parts[4]) if len(parts) >= 5 else 0.5
                        interval_seconds = float(parts[5]) if len(parts) >= 6 else 0.25
                        deadline = time.time() + timeout_s
                        last_state = "unknown"
                        last_raw = b""
                        attempts = 0
                        transition_polls = 0
                        while time.time() < deadline:
                            last_raw = qmp_startup.memdump(args.vga_address, vga_size)
                            last_state = classify_frame(last_raw)
                            if last_state == state:
                                break
                            if last_state == "transition" and state != "transition":
                                transition_polls += 1
                                if transition_polls == 1 or transition_polls % 20 == 0:
                                    print(
                                        f"drivevga {state}: waiting through transition "
                                        f"poll {transition_polls}",
                                        flush=True,
                                    )
                                time.sleep(interval_seconds)
                                continue
                            else:
                                transition_polls = 0
                            qmp_startup.key_hold(qcode, hold_seconds)
                            attempts += 1
                            print(
                                f"drivevga {state}: last={last_state}; "
                                f"sent {qcode} attempt {attempts}",
                                flush=True,
                            )
                            time.sleep(interval_seconds)
                        else:
                            timeout_path = args.out_dir / f"drivevga_timeout_{state}.bin"
                            timeout_pgm_path = args.out_dir / f"drivevga_timeout_{state}.pgm"
                            timeout_path.write_bytes(last_raw)
                            timeout_pgm_path.write_bytes(pgm_header + last_raw)
                            raise RuntimeError(
                                f"timed out driving to VGA state {state!r}; last={last_state!r}; "
                                f"attempts={attempts}"
                            )
                        print(
                            f"drivevga matched {state} after {attempts} {qcode} attempt(s)",
                            flush=True,
                        )
                        continue
                    qmp_startup.key_hold(key, 0.5)
                    print(f"key hold {key} 0.500s", flush=True)
                    time.sleep(0.15)
            finally:
                qmp_startup.close()
        if (
            args.poke
            or args.poke_file
            or args.restore_registers
            or args.call_near is not None
            or args.resume_checkpoint_script
            or args.post_restore_key
        ):
            stop, regs = prepare_restore_halt(
                gdb,
                args.timeout,
                halted_stop,
                halted_regs,
            )
            print(f"poke halt stop: {stop}", flush=True)
            for spec in args.poke_file:
                address, path = parse_poke_file(spec, regs)
                data = path.read_bytes()
                gdb.write_memory_chunked(address, data)
                print(
                    f"poke-file wrote {len(data)} bytes from {path} at 0x{address:05x}",
                    flush=True,
                )
            # Inline pokes are intentional overrides of restored snapshot files.
            for spec in args.poke:
                address, data = parse_poke(spec, regs)
                gdb.write_memory(address, data)
                print(f"poke wrote {len(data)} bytes at 0x{address:05x}", flush=True)
            if args.restore_registers:
                restored = json.loads(args.restore_registers.read_text(encoding="utf-8"))
                registers = restored.get("registers", restored)
                if not isinstance(registers, dict):
                    raise ValueError(f"restore-registers did not contain a register object: {args.restore_registers}")
                gdb.write_registers(
                    {
                        str(key): int(value)
                        for key, value in registers.items()
                    }
                )
                print(f"restored registers from {args.restore_registers}", flush=True)
                regs = gdb.registers()
            if args.call_near is not None:
                call_near_return_linear = regs["eip"]
                regs = gdb.call_near(args.call_near, regs)
                observed_call_regs = gdb.registers()
                print(
                    f"call-near pushed return IP and set CS:IP to "
                    f"{regs['cs'] & 0xffff:04x}:{args.call_near & 0xffff:04x}",
                    f" (requested EIP=0x{regs['eip']:05x}; "
                    f"observed EIP=0x{observed_call_regs['eip']:05x})",
                    flush=True,
                )
                if args.call_near_break_linear is not None:
                    call_probe_backend_address = args.call_near_break_linear
                    call_probe_expected_eip = args.call_near_break_linear
                elif call_near_break_segmented is not None:
                    call_probe_backend_address = pack_segment_offset(
                        *call_near_break_segmented
                    )
                    call_probe_expected_eip = (
                        call_near_break_segmented[0] << 4
                    ) + call_near_break_segmented[1]
                elif args.call_near_break_offset is not None:
                    offset_delta = (
                        args.call_near_break_offset
                        - (args.call_near & 0xFFFF)
                    )
                    call_probe_backend_address = (
                        observed_call_regs["eip"] + offset_delta
                    ) & 0xFFFFFFFF
                    call_probe_expected_eip = call_probe_backend_address
                else:
                    call_probe_backend_address = None
                    call_probe_expected_eip = None
                if call_probe_backend_address is not None:
                    gdb.insert_breakpoint(call_probe_backend_address)
                    gdb.continue_nowait()
                    call_probe_stop = gdb.wait_for_stop(args.timeout)
                    call_probe_regs = gdb.registers()
                    if call_probe_regs["eip"] != call_probe_expected_eip:
                        raise RuntimeError(
                            "call-near interior breakpoint stopped at the wrong "
                            "instruction: expected "
                            f"0x{call_probe_expected_eip:05x}, observed "
                            f"EIP 0x{call_probe_regs['eip']:05x}"
                        )
                    halted_stop = call_probe_stop
                    halted_regs = call_probe_regs
                    print(
                        "stopped at call-near interior breakpoint "
                        f"0x{call_probe_backend_address:05x}: "
                        f"{call_probe_stop}",
                        flush=True,
                    )
            if defer_loaded_state_continue:
                if qmp_load is None:
                    raise RuntimeError(
                        "deferred paused state load lost its QMP connection"
                    )
                # Keep the load-paused hold until all restored-state pokes and
                # the post-load breakpoint have been installed.  QMP cont
                # clears the backend hold; the GDB continue then waits for
                # either that breakpoint or the configured state-input stop.
                gdb.queue_continue()
                qmp_load.command("cont")
                qmp_load.close()
                qmp_load = None
                gdb.wait_for_continue_ack()
                halted_stop = gdb.wait_for_stop(args.timeout)
                halted_regs = gdb.registers()
                print(
                    "continued paused loaded state after pokes to capture "
                    f"boundary: {halted_stop}",
                    flush=True,
                )
            elif args.halt_after_poke:
                halted_stop = "after-poke"
                halted_regs = gdb.registers()
            elif args.call_near_continue_after_return:
                gdb.continue_nowait()
                call_return_stop = gdb.wait_for_stop(args.timeout)
                call_return_regs = gdb.registers()
                if call_return_regs["eip"] != call_near_return_linear:
                    raise RuntimeError(
                        "call-near returned to the wrong instruction: "
                        f"expected 0x{call_near_return_linear:05x}, "
                        f"observed EIP 0x{call_return_regs['eip']:05x}"
                    )
                clear_halted_breakpoint(
                    gdb,
                    call_near_return_linear,
                    args.timeout,
                )
                gdb.continue_nowait()
                halted_stop = None
                halted_regs = None
                print(
                    "continued after call-near return breakpoint: "
                    f"{call_return_stop}",
                    flush=True,
                )
            elif args.call_near_break_linear is not None:
                # The interior breakpoint already left the called function
                # halted at the requested instruction. Preserve that exact
                # boundary for the normal dump path.
                pass
            elif args.resume_checkpoint_script:
                (
                    linear_address,
                    field_name,
                    values,
                    observed_values,
                    max_hits,
                    input_events,
                    initial_held_qcodes,
                ) = resumed_state_checkpoint_plan(
                    args.resume_checkpoint_script,
                    state_input_events,
                    initial_held_qcodes=state_input_initial_held_qcodes(
                        state_input_metadata
                    ),
                )
                if args.resume_checkpoint_script.startswith("checkpointstate:"):
                    initial_held_qcodes = state_input_initial_held_qcodes(
                        state_input_metadata
                    )
                    preapplied_value = state_input_preapplied_value(
                        state_input_metadata
                    )
                    if preapplied_value is not None:
                        input_events = [
                            event
                            for event in state_input_events
                            if event[0] == preapplied_value
                        ]
                if args.resume_checkpoint_script.startswith(
                    "checkpointstatescriptfile:"
                ):
                    configured_field = state_input_metadata.get("state_field")
                    if (
                        configured_field is not None
                        and configured_field != field_name
                    ):
                        raise ValueError(
                            "state input script field "
                            f"{configured_field!r} does not match "
                            f"resume field {field_name!r}"
                        )
                if field_name not in {
                    field.name for field in state_fields
                }:
                    raise ValueError(
                        "resume checkpoint script references unknown "
                        f"schema field {field_name!r}"
                    )
                captured_values = set(values)
                if defer_loaded_state_resume:
                    if qmp_load is None:
                        raise RuntimeError(
                            "deferred paused state resume lost its QMP "
                            "connection"
                        )
                    # Clear only the QMP load hold. The debugger remains
                    # halted at the exact edited boundary. Close this client
                    # before opening the checkpoint QMP connection because
                    # the pinned backend serves one client at a time.
                    qmp_load.command("cont")
                    qmp_load.close()
                    qmp_load = None
                    print(
                        "released paused loaded state for checkpoint "
                        "continuation",
                        flush=True,
                    )
                qmp_resume = QmpClient(
                    args.host,
                    args.qmp_port,
                    args.timeout,
                )
                try:
                    def read_resumed_checkpoint_state(
                        registers: dict[str, int],
                    ) -> dict[str, int]:
                        segment = (
                            registers[args.dump_segment] & 0xFFFF
                        )
                        return read_segment_state(
                            gdb,
                            segment,
                            state_fields,
                        )

                    def capture_resumed_checkpoint(
                        value: int,
                        checkpoint_stop: str,
                        registers: dict[str, int],
                        state: dict[str, int],
                        hit_index: int,
                    ) -> None:
                        if value not in captured_values:
                            return
                        record = write_state_checkpoint(
                            qmp_resume,
                            args.out_dir / "checkpoints",
                            field_name,
                            value,
                            checkpoint_stop,
                            registers,
                            state,
                            hit_index,
                            args.dump_segment,
                            args.dump_size,
                            args.dump_low_memory,
                            args.vga_address,
                            vga_size,
                            pgm_header,
                            capture_vga=not args.omit_checkpoint_vga,
                            capture_dac=args.checkpoint_dac,
                            capture_display=args.checkpoint_displaydump,
                            capture_screenshot=(
                                args.checkpoint_screenshot
                                and post_resume_break_hit_series is None
                            ),
                            collision_namespace="resume",
                        )
                        capture_configured_post_display(
                            gdb,
                            qmp_resume,
                            args.timeout,
                            state_post_display_break,
                            state_post_display_poke,
                            record,
                            linear_address,
                            args.checkpoint_post_display_delay,
                            primary_breakpoint_installed=hit_index != 0,
                        )
                        state_checkpoints.append(record)
                        print(
                            "captured resumed state checkpoint "
                            f"{field_name}={value} on hit {hit_index}",
                            flush=True,
                        )

                    def transition_resumed_script_keys(value: int) -> None:
                        applied = replay_resumed_script_transition(
                            qmp_resume,
                            input_events,
                            value,
                            args.resume_script_event_owner,
                        )
                        if applied:
                            pressed = applied[0][1]
                            qcodes = [qcode for qcode, _ in applied]
                            print(
                                f"key {'down' if pressed else 'up'} "
                                f"{'+'.join(qcodes)} at "
                                f"{field_name}={value}",
                                flush=True,
                            )

                    def restore_resumed_held_keys() -> None:
                        if args.resume_script_event_owner == "backend":
                            return
                        for qcode in initial_held_qcodes:
                            qmp_resume.key_event(qcode, True)
                        if initial_held_qcodes:
                            print(
                                "restored held keys "
                                + "+".join(initial_held_qcodes),
                                flush=True,
                            )

                    def capture_resumed_side_breakpoint(
                        side_hit: int,
                        side_stop: str,
                        side_registers: dict[str, int],
                    ) -> None:
                        side_stack = breakpoint_stack_snapshot(
                            gdb,
                            side_registers,
                        )
                        side_writes = apply_halted_pokes(
                            gdb,
                            args.state_side_break_poke,
                            side_registers,
                        )
                        side_state = read_resumed_checkpoint_state(
                            side_registers
                        )
                        state_side_breakpoint_records.append(
                            {
                                "hit": side_hit,
                                "stop": side_stop,
                                "registers": side_registers,
                                "stack": side_stack,
                                "writes": side_writes,
                                "state": side_state,
                            }
                        )

                    restored_regs = gdb.registers()
                    if load_save_state_metadata is not None:
                        restored_regs = prepare_full_state_resume_breakpoint(
                            gdb,
                            linear_address,
                            args.timeout,
                            restored_regs,
                        )
                        restored_state = read_segment_state(
                            gdb,
                            int(
                                load_save_state_metadata[
                                    "dump_segment_value"
                                ]
                            ),
                            state_fields,
                        )
                    else:
                        restored_state = read_resumed_checkpoint_state(
                            restored_regs
                        )
                    requested_first_value = observed_values[0]
                    if load_save_state_metadata is not None:
                        actual_value = restored_state.get(field_name)
                        if not isinstance(actual_value, int):
                            raise ValueError(
                                "loaded full-state checkpoint lacks "
                                f"{field_name!r}"
                            )
                        remaining_values = (
                            full_state_resume_remaining_values(
                                actual_value,
                                observed_values,
                                input_events,
                            )
                        )
                        # A full emulator save restores guest memory and
                        # device state, but the state-input contract still
                        # owns the keyboard phase at the first observed
                        # boundary. Reapply keys held before that boundary,
                        # then consume an event exactly at the restored value.
                        # Events strictly between the saved value and the
                        # first requested checkpoint are rejected above as
                        # unsafe drift; later events remain bound to their
                        # state checkpoint callbacks.
                        restore_resumed_held_keys()
                        transition_resumed_script_keys(actual_value)
                    else:
                        validate_resume_bootstrap(
                            restored_regs,
                            restored_state,
                            field_name,
                            requested_first_value,
                            args.resume_next_linear,
                            full_state_loaded=False,
                        )
                        capture_resumed_checkpoint(
                            requested_first_value,
                            "resumed-state",
                            restored_regs,
                            restored_state,
                            0,
                        )
                        restore_resumed_held_keys()
                        transition_resumed_script_keys(
                            requested_first_value
                        )
                        remaining_values = observed_values[1:]
                    if args.post_restore_key:
                        wave_capture_active = run_simple_key_actions(
                            qmp_resume,
                            args.post_restore_key,
                            wave_capture_active,
                            gdb,
                        )
                    if not remaining_values:
                        halted_stop = "resumed-state"
                        halted_regs = restored_regs
                        matched_state = restored_state
                        hit_index = 0
                    else:
                        (
                            halted_stop,
                            halted_regs,
                            matched_state,
                            hit_index,
                        ) = stop_on_state_checkpoints(
                            gdb,
                            linear_address,
                            field_name,
                            remaining_values,
                            max_hits,
                            args.timeout,
                            read_resumed_checkpoint_state,
                            capture_resumed_checkpoint,
                            transition_resumed_script_keys,
                            True,
                            (
                                pack_segment_offset(
                                    *state_side_break_segmented
                                ),
                                (state_side_break_segmented[0] << 4)
                                + state_side_break_segmented[1],
                            )
                            if state_side_break_segmented is not None
                            else None,
                            capture_resumed_side_breakpoint
                            if state_side_break_segmented is not None
                            else None,
                            state_side_break_max_hits,
                            state_side_break_start_value,
                        )
                finally:
                    qmp_resume.close()
                break_state_match = {
                    "linear_address": linear_address,
                    "predicate": f"{field_name}=={values[-1]}",
                    "maximum_hits": max_hits,
                    "matched_hit": hit_index,
                    "state": matched_state,
                    "resumed": True,
                    "initial_held_qcodes": initial_held_qcodes,
                    "input_script_source": (
                        str(args.input_script)
                        if args.input_script is not None
                        else None
                    ),
                    "input_script_metadata": state_input_metadata,
                    "input_script": [
                        {
                            "value": value,
                            "pressed": pressed,
                            "qcodes": qcodes,
                        }
                        for value, pressed, qcodes in input_events
                    ],
                }
                print(
                    f"captured {len(values)} resumed state checkpoints "
                    f"with {len(input_events)} remaining input transitions "
                    f"at 0x{linear_address:05x}: {halted_stop}",
                    flush=True,
                )
                if direct_resume_final_poke:
                    poke_writes = apply_post_resume_pokes(
                        gdb,
                        args.post_resume_poke,
                        args.post_resume_poke_file,
                        halted_regs,
                    )
                    for write in poke_writes:
                        print(
                            "final resumed-checkpoint poke wrote "
                            f"{write['size']} bytes from "
                            f"{write.get('path', 'inline hex')} at "
                            f"0x{write['address']:05x}",
                            flush=True,
                        )
                    break_state_match[
                        "post_resume_final_checkpoint_pokes"
                    ] = poke_writes
                post_resume_display_history_start = None
                if args.post_resume_display_history_capacity > 0:
                    qmp_display_history = QmpClient(
                        args.host,
                        args.qmp_port,
                        args.timeout,
                    )
                    try:
                        post_resume_display_history_start = (
                            qmp_display_history.start_display_history(
                                args.post_resume_display_history_capacity
                            )
                        )
                    finally:
                        qmp_display_history.close()
                    print(
                        "armed post-resume completed-display history "
                        f"capacity={args.post_resume_display_history_capacity}",
                        flush=True,
                    )
                if (
                    args.post_resume_break_linear is not None
                    or post_resume_break_segmented is not None
                ):
                    if should_clear_resume_checkpoint_breakpoint(
                        linear_address,
                        args.post_resume_break_linear,
                        post_resume_break_segmented,
                        len(observed_values),
                    ):
                        halted_stop = step_past_optional_halted_breakpoint(
                            gdb,
                            linear_address,
                            args.timeout,
                        )
                        halted_regs = gdb.registers()
                    if post_resume_break_hit_series is not None:
                        breakpoint_records: list[dict[str, Any]] = []
                        qmp_breakpoints = QmpClient(
                            args.host,
                            args.qmp_port,
                            args.timeout,
                        )

                        def capture_breakpoint_hit(
                            series_hit: int,
                            series_stop: str,
                            series_registers: dict[str, int],
                        ) -> None:
                            record = write_state_checkpoint(
                                qmp_breakpoints,
                                args.out_dir / "checkpoints",
                                "breakpoint_hit",
                                series_hit,
                                series_stop,
                                series_registers,
                                {"breakpoint_hit": series_hit},
                                series_hit,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=True,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=False,
                            )
                            if args.checkpoint_screenshot:
                                if post_resume_break_segmented is not None:
                                    segment, offset = post_resume_break_segmented
                                    backend_address = pack_segment_offset(
                                        segment,
                                        offset,
                                    )
                                    screenshot_linear = (segment << 4) + offset
                                else:
                                    backend_address = args.post_resume_break_linear
                                    screenshot_linear = args.post_resume_break_linear
                                if (
                                    backend_address is None
                                    or screenshot_linear is None
                                ):
                                    raise RuntimeError(
                                        "post-resume screenshot has no breakpoint"
                                    )
                                capture_halted_breakpoint_screenshot(
                                    gdb,
                                    qmp_breakpoints,
                                    args.timeout,
                                    backend_address,
                                    screenshot_linear,
                                    args.vga_address,
                                    vga_size,
                                    record,
                                    args.checkpoint_post_display_delay,
                                    preserve_memory=(
                                        checkpoint_screenshot_preserve_memory
                                    ),
                                )
                            state_checkpoints.append(record)
                            breakpoint_records.append(record)
                            print(
                                "captured post-resume breakpoint hit "
                                f"{series_hit}",
                                flush=True,
                            )

                        try:
                            if post_resume_break_segmented is not None:
                                segment, offset = post_resume_break_segmented
                                breakpoint_description = (
                                    f"{segment:04x}:{offset:04x}"
                                )
                                (
                                    halted_stop,
                                    halted_regs,
                                ) = (
                                    stop_on_post_resume_segmented_breakpoint_series(
                                        gdb,
                                        segment,
                                        offset,
                                        post_resume_break_hit_series,
                                        args.timeout,
                                        capture_breakpoint_hit,
                                    )
                                )
                                breakpoint_address = {
                                    "segment": segment,
                                    "offset": offset,
                                }
                            else:
                                breakpoint_description = (
                                    f"0x{args.post_resume_break_linear:05x}"
                                )
                                (
                                    halted_stop,
                                    halted_regs,
                                ) = stop_on_post_resume_breakpoint_series(
                                    gdb,
                                    args.post_resume_break_linear,
                                    post_resume_break_hit_series,
                                    args.timeout,
                                    capture_breakpoint_hit,
                                )
                                breakpoint_address = {
                                    "linear_address": (
                                        args.post_resume_break_linear
                                    )
                                }
                        finally:
                            qmp_breakpoints.close()
                        break_state_match[
                            "post_resume_breakpoint_series"
                        ] = {
                            **breakpoint_address,
                            "hits": post_resume_break_hit_series,
                            "checkpoints": breakpoint_records,
                        }
                        print(
                            "captured post-resume breakpoint series "
                            f"{post_resume_break_hit_series} at "
                            f"{breakpoint_description}: {halted_stop}",
                            flush=True,
                        )
                    else:
                        if post_resume_break_segmented is not None:
                            segment, offset = post_resume_break_segmented
                            (
                                halted_stop,
                                halted_regs,
                            ) = stop_on_post_resume_nth_segmented_breakpoint(
                                gdb,
                                segment,
                                offset,
                                args.post_resume_break_hit_count,
                                args.timeout,
                            )
                            breakpoint_description = (
                                f"{segment:04x}:{offset:04x}"
                            )
                            break_state_match["post_resume_breakpoint"] = {
                                "segment": segment,
                                "offset": offset,
                                "hit_count": args.post_resume_break_hit_count,
                            }
                        else:
                            (
                                halted_stop,
                                halted_regs,
                            ) = stop_on_post_resume_nth_breakpoint(
                                gdb,
                                args.post_resume_break_linear,
                                args.post_resume_break_hit_count,
                                args.timeout,
                            )
                            breakpoint_description = (
                                f"0x{args.post_resume_break_linear:05x}"
                            )
                            break_state_match["post_resume_breakpoint"] = {
                                "linear_address": (
                                    args.post_resume_break_linear
                                ),
                                "hit_count": (
                                    args.post_resume_break_hit_count
                                ),
                            }
                        print(
                            "stopped on post-resume breakpoint hit "
                            f"{args.post_resume_break_hit_count} at "
                            f"{breakpoint_description}: {halted_stop}",
                            flush=True,
                        )
                        if direct_resume_final_poke:
                            active_breakpoint_linear = (
                                pack_segment_offset(
                                    post_resume_break_segmented[0],
                                    post_resume_break_segmented[1],
                                )
                                if post_resume_break_segmented is not None
                                else args.post_resume_break_linear
                            )
                    if post_resume_display_history_start is not None:
                        qmp_display_history = QmpClient(
                            args.host,
                            args.qmp_port,
                            args.timeout,
                        )
                        try:
                            post_resume_display_history = (
                                qmp_display_history.stop_display_history()
                            )
                        finally:
                            qmp_display_history.close()
                        history_record = write_display_history(
                            args.out_dir,
                            post_resume_display_history_start,
                            post_resume_display_history,
                        )
                        break_state_match[
                            "post_resume_display_history"
                        ] = history_record
                        print(
                            "captured post-resume completed-display history "
                            f"frames={history_record['frame_count']} "
                            f"dropped={history_record['dropped']}",
                            flush=True,
                        )
                    if has_post_resume_next_break:
                        # Preserve the first boundary before advancing to the
                        # configured next breakpoint. This is the reusable
                        # paired-boundary capture path: callers can compare
                        # DS/VGA/DAC state from both entries in one emulator
                        # run instead of aligning separate captures.
                        qmp_first_boundary = QmpClient(
                            args.host,
                            args.qmp_port,
                            args.timeout,
                        )
                        try:
                            first_boundary_record = write_state_checkpoint(
                                qmp_first_boundary,
                                args.out_dir / "checkpoints",
                                "post_resume_first",
                                1,
                                halted_stop,
                                halted_regs,
                                {"breakpoint_hit": 1},
                                1,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=True,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=args.checkpoint_screenshot,
                            )
                        finally:
                            qmp_first_boundary.close()
                        state_checkpoints.append(first_boundary_record)
                        break_state_match[
                            "post_resume_first_checkpoint"
                        ] = first_boundary_record
                        print(
                            "captured post-resume first-boundary checkpoint",
                            flush=True,
                        )
                        poke_writes = apply_post_resume_pokes(
                            gdb,
                            args.post_resume_poke,
                            args.post_resume_poke_file,
                            halted_regs,
                        )
                        for write in poke_writes:
                            print(
                                "post-resume poke wrote "
                                f"{write['size']} bytes from "
                                f"{write.get('path', 'inline hex')} at "
                                f"0x{write['address']:05x}",
                                flush=True,
                            )
                        first_backend_address = (
                            pack_segment_offset(
                                post_resume_break_segmented[0],
                                post_resume_break_segmented[1],
                            )
                            if post_resume_break_segmented is not None
                            else args.post_resume_break_linear
                        )
                        halted_stop = clear_halted_breakpoint(
                            gdb,
                            first_backend_address,
                            args.timeout,
                        )
                        if post_resume_next_break_segmented is not None:
                            next_segment, next_offset = (
                                post_resume_next_break_segmented
                            )
                            next_backend_address = pack_segment_offset(
                                next_segment,
                                next_offset,
                            )
                            next_description = (
                                f"{next_segment:04x}:{next_offset:04x}"
                            )
                            next_address_metadata = {
                                "segment": next_segment,
                                "offset": next_offset,
                            }
                        else:
                            next_backend_address = (
                                args.post_resume_next_break_linear
                            )
                            next_description = (
                                "0x"
                                f"{args.post_resume_next_break_linear:05x}"
                            )
                            next_address_metadata = {
                                "linear_address": (
                                    args.post_resume_next_break_linear
                                ),
                            }

                        if post_resume_next_break_hit_series is not None:
                            next_breakpoint_records: list[
                                dict[str, Any]
                            ] = []
                            qmp_next_breakpoints = QmpClient(
                                args.host,
                                args.qmp_port,
                                args.timeout,
                            )

                            def capture_next_breakpoint_hit(
                                series_hit: int,
                                series_stop: str,
                                series_registers: dict[str, int],
                            ) -> None:
                                record = write_state_checkpoint(
                                    qmp_next_breakpoints,
                                    args.out_dir / "checkpoints",
                                    "next_breakpoint_hit",
                                    series_hit,
                                    series_stop,
                                    series_registers,
                                    {"breakpoint_hit": series_hit},
                                    series_hit,
                                    args.dump_segment,
                                    args.dump_size,
                                    args.dump_low_memory,
                                    args.vga_address,
                                    vga_size,
                                    pgm_header,
                                    capture_vga=(
                                        not args.omit_checkpoint_vga
                                    ),
                                    capture_dac=True,
                                    capture_display=args.checkpoint_displaydump,
                                    capture_screenshot=False,
                                )
                                if args.checkpoint_screenshot:
                                    if (
                                        post_resume_next_break_segmented
                                        is not None
                                    ):
                                        screenshot_linear = (
                                            (next_segment << 4) +
                                            next_offset
                                        )
                                    else:
                                        screenshot_linear = (
                                            args.post_resume_next_break_linear
                                        )
                                    capture_halted_breakpoint_screenshot(
                                        gdb,
                                        qmp_next_breakpoints,
                                        args.timeout,
                                        next_backend_address,
                                        screenshot_linear,
                                        args.vga_address,
                                        vga_size,
                                        record,
                                        args.checkpoint_post_display_delay,
                                        preserve_memory=(
                                            checkpoint_screenshot_preserve_memory
                                        ),
                                    )
                                state_checkpoints.append(record)
                                next_breakpoint_records.append(record)
                                print(
                                    "captured post-resume next breakpoint "
                                    f"hit {series_hit}",
                                    flush=True,
                                )

                            try:
                                if (
                                    post_resume_next_break_segmented
                                    is not None
                                ):
                                    (
                                        halted_stop,
                                        halted_regs,
                                    ) = (
                                        stop_on_post_resume_segmented_breakpoint_series(
                                            gdb,
                                            next_segment,
                                            next_offset,
                                            post_resume_next_break_hit_series,
                                            args.timeout,
                                            capture_next_breakpoint_hit,
                                        )
                                    )
                                else:
                                    (
                                        halted_stop,
                                        halted_regs,
                                    ) = stop_on_post_resume_breakpoint_series(
                                        gdb,
                                        args.post_resume_next_break_linear,
                                        post_resume_next_break_hit_series,
                                        args.timeout,
                                        capture_next_breakpoint_hit,
                                    )
                            finally:
                                qmp_next_breakpoints.close()
                            next_metadata = {
                                **next_address_metadata,
                                "hits": post_resume_next_break_hit_series,
                                "checkpoints": next_breakpoint_records,
                            }
                        else:
                            if (
                                post_resume_next_break_segmented
                                is not None
                            ):
                                (
                                    halted_stop,
                                    halted_regs,
                                ) = stop_on_post_resume_nth_segmented_breakpoint(
                                    gdb,
                                    next_segment,
                                    next_offset,
                                    args.post_resume_next_break_hit_count,
                                    args.timeout,
                                )
                            else:
                                (
                                    halted_stop,
                                    halted_regs,
                                ) = stop_on_post_resume_nth_breakpoint(
                                    gdb,
                                    args.post_resume_next_break_linear,
                                    args.post_resume_next_break_hit_count,
                                    args.timeout,
                                )
                            next_metadata = {
                                **next_address_metadata,
                                "hit_count": (
                                    args.post_resume_next_break_hit_count
                                ),
                            }
                        break_state_match[
                            "post_resume_poke_files"
                        ] = poke_writes
                        break_state_match[
                            "post_resume_next_breakpoint"
                        ] = next_metadata
                        if post_resume_next_break_hit_series is not None:
                            print(
                                "captured post-resume next breakpoint "
                                f"series {post_resume_next_break_hit_series} "
                                f"at {next_description}: {halted_stop}",
                                flush=True,
                            )
                        else:
                            print(
                                "stopped on post-resume next breakpoint hit "
                                f"{args.post_resume_next_break_hit_count} at "
                                f"{next_description}: {halted_stop}",
                                flush=True,
                            )
                        if save_state_target == "post_resume_next":
                            qmp_save = QmpClient(
                                args.host,
                                args.qmp_port,
                                args.timeout,
                            )
                            try:
                                final_state = read_resumed_checkpoint_state(
                                    halted_regs
                                )
                                save_record = write_state_checkpoint(
                                    qmp_save,
                                    args.out_dir / "checkpoints",
                                    "post_resume_next",
                                    1,
                                    halted_stop,
                                    halted_regs,
                                    final_state,
                                    args.post_resume_next_break_hit_count,
                                    args.dump_segment,
                                    args.dump_size,
                                    args.dump_low_memory,
                                    args.vga_address,
                                    vga_size,
                                    pgm_header,
                                    capture_vga=not args.omit_checkpoint_vga,
                                    capture_dac=True,
                                    capture_display=args.checkpoint_displaydump,
                                    capture_screenshot=False,
                                )
                                capture_post_resume_next_display(
                                    gdb,
                                    qmp_save,
                                    args.timeout,
                                    post_display_break,
                                    post_display_poke,
                                    save_record,
                                    next_backend_address,
                                    args.checkpoint_post_display_delay,
                                )
                                state_checkpoints.append(save_record)
                                (
                                    halted_stop,
                                    halted_regs,
                                ) = finalize_halted_checkpoint_save_state(
                                    qmp_save,
                                    gdb,
                                    next_backend_address,
                                    save_record,
                                    args.timeout,
                                    lambda _registers, segment=(
                                        halted_regs[args.dump_segment]
                                        & 0xFFFF
                                    ): read_segment_state(
                                        gdb,
                                        segment,
                                        state_fields,
                                    ),
                                )
                                next_metadata["checkpoint"] = save_record
                            finally:
                                qmp_save.close()
                            print(
                                "saved post-resume next-boundary full state",
                                flush=True,
                            )
                    elif args.checkpoint_save_state_first:
                        # Save the exact post-resume boundary after any
                        # requested memory transplant, without clearing the
                        # breakpoint or executing another guest instruction.
                        # This preserves a replayable machine state immediately
                        # before the event represented by the next input tick.
                        qmp_first_boundary = QmpClient(
                            args.host,
                            args.qmp_port,
                            args.timeout,
                        )
                        try:
                            first_boundary_record = write_state_checkpoint(
                                qmp_first_boundary,
                                args.out_dir / "checkpoints",
                                "post_resume_first",
                                1,
                                halted_stop,
                                halted_regs,
                                {"breakpoint_hit": 1},
                                1,
                                args.dump_segment,
                                args.dump_size,
                                args.dump_low_memory,
                                args.vga_address,
                                vga_size,
                                pgm_header,
                                capture_vga=not args.omit_checkpoint_vga,
                                capture_dac=True,
                                capture_display=args.checkpoint_displaydump,
                                capture_screenshot=args.checkpoint_screenshot,
                            )
                            state_checkpoints.append(first_boundary_record)
                            break_state_match[
                                "post_resume_first_checkpoint"
                            ] = first_boundary_record
                            poke_writes = apply_post_resume_pokes(
                                gdb,
                                args.post_resume_poke,
                                args.post_resume_poke_file,
                                halted_regs,
                            )
                            for write in poke_writes:
                                print(
                                    "post-resume poke wrote "
                                    f"{write['size']} bytes from "
                                    f"{write.get('path', 'inline hex')} at "
                                    f"0x{write['address']:05x}",
                                    flush=True,
                                )
                            break_state_match[
                                "post_resume_poke_files"
                            ] = poke_writes
                            first_backend_address = (
                                pack_segment_offset(
                                    post_resume_break_segmented[0],
                                    post_resume_break_segmented[1],
                                )
                                if post_resume_break_segmented is not None
                                else args.post_resume_break_linear
                            )
                            (
                                halted_stop,
                                halted_regs,
                            ) = save_halted_checkpoint_state(
                                qmp_first_boundary,
                                gdb,
                                first_boundary_record,
                                halted_stop,
                                halted_regs,
                                args.timeout,
                                breakpoint_linear=first_backend_address,
                                read_post_save_state=lambda _registers, segment=(
                                    halted_regs[args.dump_segment] & 0xFFFF
                                ): read_segment_state(
                                    gdb,
                                    segment,
                                    state_fields,
                                ),
                            )
                            print(
                                "saved first post-resume boundary full state",
                                flush=True,
                            )
                        finally:
                            qmp_first_boundary.close()
                    elif (
                        args.post_resume_continue_after_poke
                        or args.post_resume_continue
                    ):
                        poke_writes = apply_post_resume_pokes(
                            gdb,
                            args.post_resume_poke,
                            args.post_resume_poke_file,
                            halted_regs,
                        )
                        for write in poke_writes:
                            print(
                                "post-resume poke wrote "
                                f"{write['size']} bytes from "
                                f"{write.get('path', 'inline hex')} at "
                                f"0x{write['address']:05x}",
                                flush=True,
                            )
                        first_backend_address = (
                            pack_segment_offset(
                                post_resume_break_segmented[0],
                                post_resume_break_segmented[1],
                            )
                            if post_resume_break_segmented is not None
                            else args.post_resume_break_linear
                        )
                        clear_halted_breakpoint(
                            gdb,
                            first_backend_address,
                            args.timeout,
                        )
                        break_state_match[
                            "post_resume_poke_files"
                        ] = poke_writes
                        if args.post_resume_continue_after_poke:
                            break_state_match[
                                "post_resume_continued_after_poke"
                            ] = True
                        break_state_match["post_resume_continued"] = True
                        gdb.continue_nowait()
                        halted_stop = None
                        halted_regs = None
                        print("continued after post-resume breakpoint", flush=True)
                if save_state_target == "resume_final":
                    if not state_checkpoints:
                        raise RuntimeError(
                            "final resumed save-state has no checkpoint"
                        )
                    final_record = state_checkpoints[-1]
                    qmp_final = QmpClient(
                        args.host,
                        args.qmp_port,
                        args.timeout,
                    )
                    try:
                        (
                            halted_stop,
                            halted_regs,
                        ) = save_halted_checkpoint_state(
                            qmp_final,
                            gdb,
                            final_record,
                            halted_stop,
                            halted_regs,
                            args.timeout,
                            breakpoint_linear=linear_address,
                            read_post_save_state=lambda _registers, segment=(
                                halted_regs[args.dump_segment] & 0xFFFF
                            ): read_segment_state(
                                gdb,
                                segment,
                                state_fields,
                            ),
                        )
                        break_state_match[
                            "resume_final_checkpoint"
                        ] = final_record
                    finally:
                        qmp_final.close()
                    print(
                        "saved final resumed checkpoint full state",
                        flush=True,
                    )
            else:
                pre_resume_restore_keys = (
                    args.load_save_state is not None
                    and bool(args.post_restore_key)
                )
                if pre_resume_restore_keys:
                    qmp_post_restore = QmpClient(args.host, args.qmp_port, args.timeout)
                    try:
                        wave_capture_active = run_simple_key_actions(
                            qmp_post_restore,
                            args.post_restore_key,
                            wave_capture_active,
                            gdb,
                        )
                    finally:
                        qmp_post_restore.close()
                gdb.continue_nowait()
                if wait_predicates:
                    # A restored state starts with a synthetic GDB stop. Once
                    # pre-resume keys have been queued and execution is
                    # released, discard that setup boundary so the generic
                    # logical-state waiter can own the next halt.
                    halted_stop = None
                    halted_regs = None
                if args.post_restore_key and not pre_resume_restore_keys:
                    qmp_post_restore = QmpClient(args.host, args.qmp_port, args.timeout)
                    try:
                        wave_capture_active = run_simple_key_actions(
                            qmp_post_restore,
                            args.post_restore_key,
                            wave_capture_active,
                            gdb,
                        )
                    finally:
                        qmp_post_restore.close()

        if halted_regs is not None:
            pass
        elif wait_predicates:
            setup_stop = gdb.halt(args.timeout)
            setup_regs = gdb.registers()
            dump_segment_value = setup_regs[args.dump_segment]
            dump_linear = dump_segment_value << 4
            print(
                f"wait-state setup halt: {setup_stop}; "
                f"{args.dump_segment}={dump_segment_value:04x}",
                flush=True,
            )
            gdb.continue_nowait()
            qmp_wait = QmpClient(args.host, args.qmp_port, args.timeout)
            deadline = time.time() + args.wait_state_timeout
            poll_count = 0
            last_state: dict[str, int] = {}
            last_failures: list[str] = []
            try:
                while time.time() < deadline:
                    poll_count += 1
                    poll_dump = qmp_wait.memdump(dump_linear, args.dump_size)
                    last_state = parse_state(poll_dump, state_fields)
                    last_failures = evaluate_state_predicates(last_state, wait_predicates)
                    if not last_failures:
                        candidate_stop = gdb.halt(args.timeout)
                        candidate_regs = gdb.registers()
                        candidate_linear = candidate_regs[args.dump_segment] << 4
                        candidate_dump = qmp_wait.memdump(candidate_linear, args.dump_size)
                        candidate_state = parse_state(candidate_dump, state_fields)
                        candidate_failures = evaluate_state_predicates(
                            candidate_state, wait_predicates
                        )
                        if not candidate_failures:
                            halted_stop = candidate_stop
                            halted_regs = candidate_regs
                            wait_state_match = {
                                "predicates": format_state_predicates(wait_predicates),
                                "polls": poll_count,
                                "state": candidate_state,
                            }
                            print(
                                "wait-state matched "
                                f"{format_state_predicates(wait_predicates)} "
                                f"after {poll_count} polls",
                                flush=True,
                            )
                            break
                        gdb.continue_nowait()
                        last_failures = candidate_failures
                    time.sleep(args.wait_state_interval)
                else:
                    timeout_state_path = args.out_dir / "wait_state_timeout.json"
                    timeout_state_path.write_text(
                        json.dumps(
                            {
                                "predicates": format_state_predicates(wait_predicates),
                                "polls": poll_count,
                                "last_state": last_state,
                                "last_failures": last_failures,
                            },
                            indent=2,
                            sort_keys=True,
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    raise RuntimeError(
                        "timed out waiting for state "
                        f"{format_state_predicates(wait_predicates)}; "
                        f"last failures: {'; '.join(last_failures)}"
                    )
            finally:
                qmp_wait.close()
        else:
            time.sleep(args.delay)
            halted_stop = gdb.halt(args.timeout)
            halted_regs = gdb.registers()

        post_wait_continued = False
        if args.post_wait_key:
            if not wait_predicates:
                parser.error("--post-wait-key requires --wait-state")
            gdb.continue_nowait()
            post_wait_continued = True
            qmp_post_wait = QmpClient(args.host, args.qmp_port, args.timeout)
            try:
                wave_capture_active = run_simple_key_actions(
                    qmp_post_wait,
                    args.post_wait_key,
                    wave_capture_active,
                    gdb,
                )
            finally:
                qmp_post_wait.close()
            print(
                f"queued {len(args.post_wait_key)} post-wait key action(s)",
                flush=True,
            )

        # A backend state-input stop is already a resumable guest boundary.
        # Allow a repeated post-boundary breakpoint series without requiring a
        # second state-schema resume script.  This is useful when the state
        # hook is the only safe way to reach a late presenter or device call.
        state_input_post_break = (
            args.state_input_stop_value is not None
            and args.resume_checkpoint_script is None
            and (
                args.post_resume_break_linear is not None
                or post_resume_break_segmented is not None
            )
        )
        if state_input_post_break:
            if halted_stop is None or halted_regs is None:
                raise RuntimeError(
                    "state-input post-resume breakpoint has no halted boundary"
                )
            qmp_post_resume = QmpClient(
                args.host,
                args.qmp_port,
                args.timeout,
            )

            def capture_state_input_breakpoint(
                series_hit: int,
                series_stop: str,
                series_registers: dict[str, int],
            ) -> None:
                segment = series_registers[args.dump_segment] & 0xFFFF
                series_state = read_segment_state(
                    gdb,
                    segment,
                    state_fields,
                )
                record = write_state_checkpoint(
                    qmp_post_resume,
                    args.out_dir / "checkpoints",
                    "breakpoint_hit",
                    series_hit,
                    series_stop,
                    series_registers,
                    series_state,
                    series_hit,
                    args.dump_segment,
                    args.dump_size,
                    args.dump_low_memory,
                    args.vga_address,
                    vga_size,
                    pgm_header,
                    capture_vga=not args.omit_checkpoint_vga,
                    capture_dac=args.checkpoint_dac,
                    capture_display=args.checkpoint_displaydump,
                    capture_screenshot=args.checkpoint_screenshot,
                )
                state_checkpoints.append(record)

            try:
                if post_resume_break_hit_series is not None:
                    if post_resume_break_segmented is not None:
                        segment, offset = post_resume_break_segmented
                        (
                            halted_stop,
                            halted_regs,
                        ) = stop_on_post_resume_breakpoint_series_at_backend_address(
                            gdb,
                            pack_segment_offset(segment, offset),
                            (segment << 4) + offset,
                            post_resume_break_hit_series,
                            args.timeout,
                            capture_state_input_breakpoint,
                        )
                    else:
                        (
                            halted_stop,
                            halted_regs,
                        ) = stop_on_post_resume_breakpoint_series(
                            gdb,
                            args.post_resume_break_linear,
                            post_resume_break_hit_series,
                            args.timeout,
                            capture_state_input_breakpoint,
                        )
                elif post_resume_break_segmented is not None:
                    segment, offset = post_resume_break_segmented
                    (
                        halted_stop,
                        halted_regs,
                    ) = stop_on_post_resume_nth_segmented_breakpoint(
                        gdb,
                        segment,
                        offset,
                        args.post_resume_break_hit_count,
                        args.timeout,
                    )
                else:
                    (
                        halted_stop,
                        halted_regs,
                    ) = stop_on_post_resume_nth_breakpoint(
                        gdb,
                        args.post_resume_break_linear,
                        args.post_resume_break_hit_count,
                        args.timeout,
                    )
            finally:
                qmp_post_resume.close()
            break_state_match = {
                "linear_address": (
                    args.post_resume_break_linear
                    if args.post_resume_break_linear is not None
                    else (post_resume_break_segmented[0] << 4)
                    + post_resume_break_segmented[1]
                ),
                "predicate": "state_input_stop",
                "maximum_hits": args.post_resume_break_hit_count,
                "state": read_segment_state(
                    gdb,
                    halted_regs[args.dump_segment] & 0xFFFF,
                    state_fields,
                ),
                "post_resume_breakpoint_series": (
                    post_resume_break_hit_series
                ),
            }
            print(
                "captured state-input post-resume breakpoint boundary",
                flush=True,
            )

        recovered_checkpoint_screenshots = (
            recover_checkpoint_screenshot_side_effects(
                args.out_dir,
                state_checkpoints,
                checkpoint_screenshot_baseline,
            )
            if args.checkpoint_screenshot
            else 0
        )
        if recovered_checkpoint_screenshots:
            print(
                "recovered "
                f"{recovered_checkpoint_screenshots} deferred checkpoint "
                "screenshots",
                flush=True,
            )

        if args.vga_sequence_frames < 0:
            raise ValueError("--vga-sequence-frames must be non-negative")
        if args.vga_sequence_interval <= 0:
            raise ValueError("--vga-sequence-interval must be positive")
        if args.display_sequence_frames < 0:
            raise ValueError("--display-sequence-frames must be non-negative")
        if args.display_sequence_interval <= 0:
            raise ValueError("--display-sequence-interval must be positive")
        if args.vga_sequence_frames > 0 and args.display_sequence_frames > 0:
            raise ValueError(
                "VGA and completed-display sequences cannot run together"
            )

        if args.vga_sequence_frames > 0:
            sequence_dir = args.out_dir / "vga_sequence"
            sequence_dir.mkdir(parents=True, exist_ok=True)
            sequence_rows: list[dict[str, Any]] = []
            previous_vga: bytes | None = None
            previous_dac: bytes | None = None
            sequence_start = time.perf_counter()
            if active_breakpoint_linear is not None:
                # A software breakpoint reports the instruction boundary but
                # leaves the guest halted there.  Continuing without removing
                # it re-enters the same breakpoint on every VGA sample.  The
                # sequence is a post-boundary observation, so release that
                # reusable capture breakpoint before sampling the timeline.
                gdb.remove_breakpoint(active_breakpoint_linear)
                print(
                    "removed halted linear breakpoint before VGA sequence "
                    f"at 0x{active_breakpoint_linear:05x}",
                    flush=True,
                )
                active_breakpoint_linear = None
            if not post_wait_continued:
                gdb.continue_nowait()
            qmp_sequence = QmpClient(args.host, args.qmp_port, args.timeout)
            try:
                for index in range(args.vga_sequence_frames):
                    target = sequence_start + index * args.vga_sequence_interval
                    remaining = target - time.perf_counter()
                    if remaining > 0:
                        time.sleep(remaining)
                    sample_started = time.perf_counter()
                    raw = qmp_sequence.memdump(args.vga_address, vga_size)
                    dac_dump = qmp_sequence.dacdump()
                    sample = write_vga_dac_sequence_sample(
                        sequence_dir,
                        index,
                        raw,
                        dac_dump,
                    )
                    screen_path: Path | None = None
                    screenshot_error: str | None = None
                    screenshot_deferred_side_effect = False
                    if should_capture_vga_sequence_screenshot(
                        args.vga_sequence_screenshot_all,
                        args.vga_sequence_screenshot_on_stop,
                        args.vga_sequence_stop_sha256,
                        sample["sha256"],
                    ):
                        screen_path = sequence_dir / f"frame_{index:04d}.png"
                        (
                            screenshot_error,
                            screenshot_deferred_side_effect,
                        ) = capture_targeted_sequence_screenshot(
                            qmp_sequence,
                            screen_path,
                            args.out_dir,
                        )
                        if screenshot_error is not None:
                            screen_path = None
                            print(
                                f"sequence screenshot {index} skipped: "
                                f"{screenshot_error}",
                                flush=True,
                            )
                    memory_data: bytes | None = None
                    memory_linear: int | None = None
                    memory_segment_value: int | None = None
                    memory_cs: int | None = None
                    memory_eip: int | None = None
                    if args.dump_size > 0:
                        # QMP memory reads while the guest is running are not
                        # a reliable semantic checkpoint on all DOSBox-X
                        # builds. Halt immediately after the VGA/DAC/screen
                        # sample, read the live segment register, then resume
                        # the sequence. The memory artifact is therefore
                        # explicitly paired with a halted post-sample state.
                        gdb.halt(args.timeout)
                        memory_registers = gdb.registers()
                        memory_segment_value = (
                            memory_registers[args.dump_segment] & 0xFFFF
                        )
                        memory_linear = memory_segment_value << 4
                        memory_cs = memory_registers.get("cs")
                        memory_eip = memory_registers.get("eip")
                        memory_data = qmp_memory_dump(
                            qmp_sequence,
                            memory_linear,
                            args.dump_size,
                        )
                        sample = write_vga_dac_sequence_sample(
                            sequence_dir,
                            index,
                            raw,
                            dac_dump,
                            memory_data=memory_data,
                            memory_segment=args.dump_segment,
                            memory_linear=memory_linear,
                            memory_segment_value=memory_segment_value,
                            memory_cs=memory_cs,
                            memory_eip=memory_eip,
                        )
                        gdb.continue_nowait()
                    sample_finished = time.perf_counter()
                    changed_pixels = (
                        0
                        if previous_vga is None
                        else sum(left != right for left, right in zip(previous_vga, raw))
                    )
                    changed_dac_bytes = (
                        0
                        if previous_dac is None
                        else sum(
                            left != right
                            for left, right in zip(previous_dac, dac_dump["data"])
                        )
                    )
                    frame_sha256 = sample["sha256"]
                    sequence_rows.append(
                        {
                            "index": index,
                            "scheduled_seconds": index * args.vga_sequence_interval,
                            "sample_started_seconds": sample_started - sequence_start,
                            "sample_finished_seconds": sample_finished - sequence_start,
                            "changed_pixels_from_previous": changed_pixels,
                            "changed_dac_bytes_from_previous": changed_dac_bytes,
                            **sample,
                            "screenshot": str(screen_path) if screen_path else None,
                            "screenshot_error": screenshot_error,
                            "screenshot_deferred_side_effect": (
                                screenshot_deferred_side_effect
                            ),
                        }
                    )
                    previous_vga = raw
                    previous_dac = dac_dump["data"]
                    if (args.vga_sequence_stop_sha256 and (
                        frame_sha256 == args.vga_sequence_stop_sha256.lower()
                    )):
                        break
            finally:
                qmp_sequence.close()
            halted_stop = gdb.halt(args.timeout)
            halted_regs = gdb.registers()
            sequence_manifest = args.out_dir / "vga_sequence.json"
            sequence_manifest.write_text(
                json.dumps(
                    {
                        "frame_count": len(sequence_rows),
                        "requested_interval_seconds": args.vga_sequence_interval,
                        "memory_segment": (
                            args.dump_segment
                            if args.dump_size > 0
                            else None
                        ),
                        "memory_size": (
                            args.dump_size
                            if args.dump_size > 0
                            else 0
                        ),
                        "memory_linear": "per-sample-halted"
                        if args.dump_size > 0
                        else None,
                        "frames": sequence_rows,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"wrote {sequence_manifest}", flush=True)

        elif args.display_sequence_frames > 0:
            sequence_dir = args.out_dir / "display_sequence"
            sequence_dir.mkdir(parents=True, exist_ok=True)
            sequence_rows: list[dict[str, Any]] = []
            previous_display: bytes | None = None
            previous_dac: bytes | None = None
            previous_generation: int | None = None
            sequence_start = time.perf_counter()
            if active_breakpoint_linear is not None:
                gdb.remove_breakpoint(active_breakpoint_linear)
                print(
                    "removed halted linear breakpoint before display sequence "
                    f"at 0x{active_breakpoint_linear:05x}",
                    flush=True,
                )
                active_breakpoint_linear = None
            if not post_wait_continued:
                gdb.continue_nowait()
            qmp_sequence = QmpClient(args.host, args.qmp_port, args.timeout)
            try:
                for index in range(args.display_sequence_frames):
                    target = (
                        sequence_start
                        + index * args.display_sequence_interval
                    )
                    remaining = target - time.perf_counter()
                    if remaining > 0:
                        time.sleep(remaining)
                    sample_started = time.perf_counter()
                    display_dump = qmp_sequence.displaydump()
                    dac_dump = qmp_sequence.dacdump()
                    sample = write_display_dac_sequence_sample(
                        sequence_dir,
                        index,
                        display_dump,
                        dac_dump,
                    )
                    sample_finished = time.perf_counter()
                    display_data = display_dump["data"]
                    dac_data = dac_dump["data"]
                    generation = display_dump["generation"]
                    sequence_rows.append(
                        {
                            "index": index,
                            "scheduled_seconds": (
                                index * args.display_sequence_interval
                            ),
                            "sample_started_seconds": (
                                sample_started - sequence_start
                            ),
                            "sample_finished_seconds": (
                                sample_finished - sequence_start
                            ),
                            "generation_delta": (
                                0
                                if previous_generation is None
                                else generation - previous_generation
                            ),
                            "changed_display_bytes_from_previous": (
                                0
                                if previous_display is None
                                else sum(
                                    left != right
                                    for left, right in zip(
                                        previous_display,
                                        display_data,
                                    )
                                )
                            ),
                            "changed_dac_bytes_from_previous": (
                                0
                                if previous_dac is None
                                else sum(
                                    left != right
                                    for left, right in zip(
                                        previous_dac,
                                        dac_data,
                                    )
                                )
                            ),
                            **sample,
                        }
                    )
                    previous_display = display_data
                    previous_dac = dac_data
                    previous_generation = generation
            finally:
                qmp_sequence.close()
            halted_stop = gdb.halt(args.timeout)
            halted_regs = gdb.registers()
            sequence_manifest = args.out_dir / "display_sequence.json"
            sequence_manifest.write_text(
                json.dumps(
                    {
                        "frame_count": len(sequence_rows),
                        "requested_interval_seconds": (
                            args.display_sequence_interval
                        ),
                        "source": "last_completed_renderer_source_frame",
                        "frames": sequence_rows,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"wrote {sequence_manifest}", flush=True)

        elif post_wait_continued:
            halted_stop = gdb.halt(args.timeout)
            halted_regs = gdb.registers()

        side_trace_path: Path | None = None
        if state_side_break_segmented is not None:
            side_trace_path = args.out_dir / "side_breakpoint_trace.json"
            side_trace_path.write_text(
                json.dumps(
                    {
                        "segment": state_side_break_segmented[0],
                        "offset": state_side_break_segmented[1],
                        "expected_eip": (state_side_break_segmented[0] << 4)
                        + state_side_break_segmented[1],
                        "max_hits": state_side_break_max_hits,
                        "start_value": state_side_break_start_value,
                        "poke_specs": args.state_side_break_poke,
                        "truncated": (
                            state_side_break_max_hits is not None
                            and len(state_side_breakpoint_records)
                            >= state_side_break_max_hits
                        ),
                        "hits": state_side_breakpoint_records,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            if break_state_match is not None:
                break_state_match["side_breakpoint_trace"] = {
                    "segment": state_side_break_segmented[0],
                    "offset": state_side_break_segmented[1],
                    "path": str(side_trace_path),
                    "hit_count": len(state_side_breakpoint_records),
                    "max_hits": state_side_break_max_hits,
                    "start_value": state_side_break_start_value,
                }

        stop = halted_stop
        regs = halted_regs
        if stop is None or regs is None:
            raise RuntimeError("internal error: final capture was not halted")
        qmp = QmpClient(args.host, args.qmp_port, args.timeout)
        if save_state_target == "state_input_stop":
            if args.state_input_stop_value is None:
                raise RuntimeError(
                    "state-input save-state target lacks a stop value"
                )
            target_value = int(args.state_input_stop_value, 0)
            target_state = read_segment_state(
                gdb,
                regs[args.dump_segment] & 0xFFFF,
                state_fields,
            )
            checkpoint_record = write_state_checkpoint(
                qmp,
                args.out_dir / "checkpoints",
                "state_input_stop",
                target_value,
                stop,
                regs,
                target_state,
                0,
                args.dump_segment,
                args.dump_size,
                args.dump_low_memory,
                args.vga_address,
                vga_size,
                pgm_header,
                capture_vga=not args.omit_checkpoint_vga,
                capture_dac=args.checkpoint_dac,
                capture_display=args.checkpoint_displaydump,
                capture_screenshot=args.checkpoint_screenshot,
            )
            state_checkpoints.append(checkpoint_record)
            (
                stop,
                regs,
            ) = finalize_halted_state_input_save_state(
                qmp,
                gdb,
                checkpoint_record,
                stop,
                regs,
                args.timeout,
                lambda _registers: read_segment_state(
                    gdb,
                    _registers[args.dump_segment] & 0xFFFF,
                    state_fields,
                ),
            )
            halted_stop = stop
            halted_regs = regs
            print(
                "saved state-input stop full state at "
                f"{args.state_input_stop_value}",
                flush=True,
            )
        wave_capture_stop_queued = False
        if wave_capture_active:
            qmp.capture_wave(False)
            wave_capture_active = False
            wave_capture_stop_queued = True
            print("queued capture wave auto-stop at final halt", flush=True)
        dump_segment = regs[args.dump_segment]
        ds_linear = dump_segment << 4
        dump = qmp_memory_dump(qmp, ds_linear, args.dump_size)
        vga_dump = qmp_memory_dump(qmp, args.vga_address, vga_size)
        lowmem_dump = (
            qmp_memory_dump(qmp, 0x00000, 0xA0000)
            if args.dump_low_memory
            else None
        )

        dump_path = args.out_dir / "remote_runtime_ds.bin"
        vga_path = args.out_dir / "remote_runtime_vga.bin"
        vga_pgm_path = args.out_dir / "remote_runtime_vga.pgm"
        lowmem_path = args.out_dir / "remote_runtime_lowmem.bin"
        screenshot_path = args.out_dir / "remote_runtime_screen.png"
        regs_path = args.out_dir / "remote_runtime_registers.json"
        dump_path.write_bytes(dump)
        vga_path.write_bytes(vga_dump)
        vga_pgm_path.write_bytes(pgm_header + vga_dump)
        if lowmem_dump is not None:
            lowmem_path.write_bytes(lowmem_dump)
        try:
            if args.screenshot and args.vga_sequence_frames == 0:
                screenshot_path.write_bytes(qmp.screendump())
            else:
                screenshot_path = None
        except Exception as exc:
            screenshot_path = None
            print(f"screenshot skipped: {exc}", flush=True)
        regs_path.write_text(
            json.dumps(
                {
                    "stop": stop,
                    "initial_halt": initial,
                    "registers": regs,
                    "ds_linear": ds_linear,
                    "dump_segment": args.dump_segment,
                    "dump_segment_value": dump_segment,
                    "remote_ports": {
                        "host": args.host,
                        "gdb_port": args.gdb_port,
                        "qmp_port": args.qmp_port,
                    },
                    "dump": str(dump_path),
                    "dump_size": len(dump),
                    "low_memory_dump": str(lowmem_path) if lowmem_dump is not None else None,
                    "low_memory_size": len(lowmem_dump) if lowmem_dump is not None else 0,
                    "screenshot": str(screenshot_path) if screenshot_path else None,
                    "vga_dump": str(vga_path),
                    "vga_pgm": str(vga_pgm_path),
                    "delay_seconds": args.delay,
                    "wait_state": wait_state_match,
                    "break_state": break_state_match,
                    "state_checkpoints": state_checkpoints,
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
                encoding="utf-8",
            )
        final_post_display_record: dict[str, Any] | None = None
        if (
            final_post_display_break is not None
            and final_post_display_poke is not None
        ):
            final_post_display_record = capture_final_post_display(
                gdb,
                qmp,
                args.timeout,
                final_post_display_break,
                final_post_display_poke,
                args.out_dir,
                stop,
                initial,
                regs,
                args.dump_segment,
                len(dump),
                args.final_post_display_delay,
                value=args.final_post_display_value,
                primary_breakpoint=active_breakpoint_linear,
            )
            state_checkpoints.append(final_post_display_record)
            root_metadata = json.loads(regs_path.read_text(encoding="utf-8"))
            root_metadata["state_checkpoints"] = state_checkpoints
            root_metadata["final_post_display"] = final_post_display_record
            regs_path.write_text(
                json.dumps(root_metadata, indent=2, sort_keys=True) + "\n",
                encoding="utf-8",
            )
            print(
                "captured final post-display checkpoint at "
                f"{final_post_display_record['path']}",
                flush=True,
            )
        screenshot_provenance_path = write_screenshot_provenance_manifest(
            args.out_dir,
            state_checkpoints,
        )
        wave_finalization_path: Path | None = None
        if wave_capture_stop_queued:
            # The pinned backend acknowledges QMP input events on its socket
            # thread but applies them on the emulation thread. Preserve all
            # halted-state evidence first, then release execution so the
            # queued stop can close and finalize the RIFF header.
            gdb.continue_nowait()
            finalized_waves = wait_for_finalized_wave_files(
                args.out_dir,
                args.timeout,
            )
            wave_finalization_path = (
                args.out_dir / "wave-capture-finalization.json"
            )
            wave_finalization_path.write_text(
                json.dumps(
                    {
                        "format_version": 1,
                        "method": (
                            "queued_qmp_stop_serviced_after_final_"
                            "halted_state_evidence"
                        ),
                        "state_evidence_written_before_continue": True,
                        "waves": [path.name for path in finalized_waves],
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(
                f"finalized {len(finalized_waves)} wave capture(s)",
                flush=True,
            )
        summary_path = write_capture_summary(args.out_dir)

        print(f"halt stop: {stop}", flush=True)
        print(
            "registers: "
            f"cs={regs['cs']:04x} eip={regs['eip']:08x} "
            f"ds={regs['ds']:04x} ss={regs['ss']:04x} sp={regs['esp'] & 0xffff:04x}",
            flush=True,
        )
        print(f"wrote {regs_path}", flush=True)
        print(f"wrote {summary_path}", flush=True)
        if screenshot_provenance_path is not None:
            print(f"wrote {screenshot_provenance_path}", flush=True)
        if wave_finalization_path is not None:
            print(f"wrote {wave_finalization_path}", flush=True)
        print(f"wrote {dump_path} ({len(dump)} bytes from linear 0x{ds_linear:05x})", flush=True)
        if lowmem_dump is not None:
            print(f"wrote {lowmem_path} ({len(lowmem_dump)} bytes from linear 0x00000)", flush=True)
        print(f"wrote {vga_pgm_path}", flush=True)
        if screenshot_path:
            print(f"wrote {screenshot_path}", flush=True)
        return 0
    finally:
        QmpClient.set_memory_fallback(None)
        gdb.close()
        if qmp_load is not None:
            qmp_load.close()
        if "qmp" in locals():
            qmp.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"remote runtime dump failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
