#!/usr/bin/env python3
"""Control a remotedebug DOSBox-X instance and capture runtime evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import select
import socket
import struct
import sys
import time
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

    def write_memory_chunked(self, address: int, data: bytes, chunk_size: int = 4096) -> None:
        for offset in range(0, len(data), chunk_size):
            self.write_memory(address + offset, data[offset : offset + chunk_size])


def pack_segment_offset(segment: int, offset: int) -> int:
    if not 0 <= segment <= 0xFFFF:
        raise ValueError(f"breakpoint segment is outside 16-bit range: {segment}")
    if not 0 <= offset <= 0xFFFF:
        raise ValueError(f"breakpoint offset is outside 16-bit range: {offset}")
    return (segment << 16) | offset


def parse_segmented_nth_breakpoint_action(
    action: str,
) -> tuple[int, int]:
    parts = action.split(":")
    if len(parts) != 4 or parts[0] != "breaksonth":
        raise ValueError(
            "breaksonth action syntax: "
            "breaksonth:<segment>:<offset>:<positive-hit-count>"
        )
    segment = int(parts[1], 0)
    offset = int(parts[2], 0)
    hit_count = int(parts[3], 0)
    if hit_count < 1:
        raise ValueError("breakpoint hit count must be positive")
    return pack_segment_offset(segment, offset), hit_count


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
    if registers["eip"] != expected_eip:
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
    segment = int(parts[0], 0)
    offset = int(parts[1], 0)
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


class QmpClient:
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

    def command(self, execute: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        msg: dict[str, Any] = {"execute": execute}
        if arguments is not None:
            msg["arguments"] = arguments
        self.sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
        response = self._recv_json()
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
        response = self.command("memdump", {"address": address, "size": size})
        payload = response.get("return", {}).get("data")
        if not isinstance(payload, str):
            raise RuntimeError(f"QMP memdump did not return base64 data: {response}")
        return base64.b64decode(payload)

    def screendump(self) -> bytes:
        response = self.command("screendump")
        payload = response.get("return", {}).get("data")
        if not isinstance(payload, str):
            raise RuntimeError(f"QMP screendump did not return base64 data: {response}")
        return base64.b64decode(payload)


def capture_optional_screenshot(
    qmp: Any,
    path: Path,
) -> str | None:
    try:
        data = qmp.screendump()
    except RuntimeError as exc:
        return str(exc)
    path.write_bytes(data)
    return None


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
        if record.get("screenshot_requested") is True
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
        if not destination.exists():
            destination.write_bytes(source.read_bytes())
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
    capture_screenshot: bool = False,
) -> dict[str, Any]:
    checkpoint_path = checkpoint_root / f"{field_name}-{value}"
    checkpoint_path.mkdir(parents=True, exist_ok=False)
    dump_segment_value = registers[dump_segment_name] & 0xFFFF
    dump_linear = dump_segment_value << 4
    dump = qmp.memdump(dump_linear, dump_size)
    vga_dump = (
        qmp.memdump(vga_address, vga_size)
        if capture_vga
        else None
    )
    low_memory_dump = (
        qmp.memdump(0x00000, 0xA0000)
        if dump_low_memory
        else None
    )

    dump_path = checkpoint_path / "remote_runtime_ds.bin"
    vga_path = checkpoint_path / "remote_runtime_vga.bin"
    vga_pgm_path = checkpoint_path / "remote_runtime_vga.pgm"
    low_memory_path = checkpoint_path / "remote_runtime_lowmem.bin"
    screenshot_path = checkpoint_path / "remote_runtime_screen.png"
    registers_path = checkpoint_path / "remote_runtime_registers.json"
    dump_path.write_bytes(dump)
    if vga_dump is not None:
        vga_path.write_bytes(vga_dump)
        vga_pgm_path.write_bytes(pgm_header + vga_dump)
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


def run_simple_key_actions(qmp: QmpClient, actions: list[str]) -> None:
    for action in actions:
        if action.startswith("wait:"):
            seconds = float(action.split(":", 1)[1])
            time.sleep(seconds)
            print(f"post-restore wait {seconds:.3f}s", flush=True)
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
            qmp.capture_wave(operation == "start")
            print(f"post-restore capture wave {operation}", flush=True)
            continue
        qmp.key_hold(action, 0.5)
        print(f"post-restore key hold {action} 0.500s", flush=True)


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
        int(parts[1], 0),
        int(parts[2], 0),
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


def validate_state_input_events(
    events: list[tuple[int, bool, list[str]]],
) -> None:
    if not events:
        raise ValueError("state input script requires at least one event")
    held: set[str] = set()
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
    validate_state_input_events(events)
    return metadata, events


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
    held: set[str] = set()
    for value, pressed, qcodes in events:
        if value >= first_value:
            break
        for qcode in qcodes:
            if pressed:
                held.add(qcode)
            else:
                held.remove(qcode)
    if held:
        raise ValueError(
            "resumed state input scripts require a neutral keyboard boundary; "
            f"held before {first_value}: {', '.join(sorted(held))}"
        )
    resumed_events = [
        event
        for event in events
        if first_value <= event[0] <= last_value
    ]
    return (
        merged_state_script_values(capture_values, resumed_events),
        resumed_events,
    )


def resumed_state_checkpoint_plan(
    action: str,
    events: list[tuple[int, bool, list[str]]],
) -> tuple[
    int,
    str,
    list[int],
    list[int],
    int,
    list[tuple[int, bool, list[str]]],
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
        )
    if action.startswith("checkpointstatescriptfile:"):
        linear_address, field_name, capture_values, max_hits = (
            parse_state_checkpoint_script_file_action(action)
        )
        observed_values, resumed_events = resumed_state_script_plan(
            capture_values,
            events,
        )
        return (
            linear_address,
            field_name,
            capture_values,
            observed_values,
            max_hits,
            resumed_events,
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
) -> tuple[str, dict[str, int], dict[str, int], int]:
    if not values:
        raise ValueError("state checkpoint values must not be empty")
    if max_hits < 1:
        raise ValueError("state checkpoint maximum hit count must be positive")
    if not initially_halted:
        gdb.halt(timeout)
    gdb.insert_breakpoint(linear_address)
    next_value_index = 0
    for hit_index in range(1, max_hits + 1):
        gdb.continue_nowait()
        stop = gdb.wait_for_stop(timeout)
        registers = gdb.registers()
        state = read_state(registers)
        if field_name not in state:
            raise ValueError(
                f"state checkpoint field {field_name!r} is missing"
            )
        value = values[next_value_index]
        if state[field_name] == value:
            capture_match(value, stop, registers, state, hit_index)
            if after_capture is not None:
                after_capture(value)
            next_value_index += 1
            if next_value_index == len(values):
                return stop, registers, state, hit_index
        if hit_index < max_hits:
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
    parser.add_argument("--halt-after-poke", action="store_true",
                        help="Capture immediately after pokes/register restore instead of continuing")
    parser.add_argument("--post-restore-key", action="append", default=[],
                        help="After pokes/register restore and continue, send wait/tap/hold/bare key actions")
    parser.add_argument(
        "--resume-checkpoint-script",
        help=(
            "After state-file pokes, capture and continue at state "
            "boundaries. Syntax: checkpointstate:<linear-address>:<field>:"
            "<value>[+<value>...]:<positive-maximum-hit-count>, or "
            "checkpointstatescriptfile with the same fields. The latter "
            "requires --input-script and a neutral keyboard boundary."
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
        "--post-resume-poke-file",
        action="append",
        default=[],
        help=(
            "At the post-resume breakpoint, write a binary file before "
            "continuing to --post-resume-next-break-*. Uses the same forms "
            "as --poke-file."
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
        "--checkpoint-screenshot",
        action="store_true",
        help=(
            "Capture a QMP screenshot while halted at each nested state "
            "checkpoint."
        ),
    )
    parser.add_argument("--screenshot", action="store_true")
    parser.add_argument("--delay", type=float, default=4.0)
    parser.add_argument(
        "--wait-state",
        action="append",
        default=[],
        help="Schema field predicate to wait for after startup/pokes, e.g. frame_tick=3132. Repeatable.",
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
    args = parser.parse_args()
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
    if wait_predicates and not state_fields:
        parser.error("--wait-state requires --state-schema")
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
        if not args.poke_file:
            parser.error(
                "--resume-checkpoint-script requires at least one --poke-file"
            )
        if args.restore_registers is not None:
            parser.error(
                "--resume-checkpoint-script cannot use --restore-registers; "
                "the pinned DOSBox-X backend cannot continue after a full "
                "register write"
            )
        if args.resume_next_linear is None:
            parser.error(
                "--resume-checkpoint-script requires --resume-next-linear"
            )
        if args.halt_after_poke or args.post_restore_key:
            parser.error(
                "--resume-checkpoint-script cannot be combined with "
                "--halt-after-poke or --post-restore-key"
            )
    if (
        (
            args.post_resume_break_linear is not None
            or post_resume_break_segmented is not None
        )
        and not args.resume_checkpoint_script
    ):
        parser.error(
            "post-resume breakpoints require "
            "--resume-checkpoint-script"
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
    if args.post_resume_poke_file and not has_post_resume_next_break:
        parser.error(
            "--post-resume-poke-file requires "
            "--post-resume-next-break-linear or "
            "--post-resume-next-break-segmented"
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
    if post_resume_break_hit_series is not None and (
        has_post_resume_next_break or args.post_resume_poke_file
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

    gdb = RspClient(args.host, args.gdb_port, args.timeout)
    try:
        halted_stop: str | None = None
        halted_regs: dict[str, int] | None = None
        wait_state_match: dict[str, Any] | None = None
        break_state_match: dict[str, Any] | None = None
        state_checkpoints: list[dict[str, Any]] = []
        initial = gdb.packet("?")
        if initial.startswith(("S", "T")):
            # The remotedebug fork starts halted when a GDB client is attached.
            if args.break_linear is not None:
                gdb.insert_breakpoint(args.break_linear)
                print(
                    f"inserted linear breakpoint at 0x{args.break_linear:05x}",
                    flush=True,
                )
            gdb.continue_nowait()

        args.out_dir.mkdir(parents=True, exist_ok=True)
        checkpoint_screenshot_baseline = set(args.out_dir.glob("*.png"))
        (args.out_dir / "remote_runtime_args.json").write_text(
            json.dumps(
                {
                    "startup_key": args.startup_key,
                    "wait_state": args.wait_state,
                    "vga_sequence_frames": args.vga_sequence_frames,
                    "vga_sequence_interval": args.vga_sequence_interval,
                    "omit_checkpoint_vga": args.omit_checkpoint_vga,
                    "checkpoint_screenshot": args.checkpoint_screenshot,
                    "break_linear": args.break_linear,
                    "poke_file": args.poke_file,
                    "restore_registers": (
                        str(args.restore_registers)
                        if args.restore_registers is not None
                        else None
                    ),
                    "resume_checkpoint_script": (
                        args.resume_checkpoint_script
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
                    "resume_next_linear": args.resume_next_linear,
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
                                capture_screenshot=args.checkpoint_screenshot,
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
                    if key.startswith("capture-wave:"):
                        operation = key.split(":", 1)[1]
                        if operation not in {"start", "stop"}:
                            raise ValueError(
                                "capture-wave syntax: capture-wave:start|stop, "
                                f"got {key!r}"
                            )
                        qmp_startup.capture_wave(operation == "start")
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
                regs = gdb.call_near(args.call_near, regs)
                print(
                    f"call-near pushed return IP and set CS:IP to "
                    f"{regs['cs'] & 0xffff:04x}:{args.call_near & 0xffff:04x}",
                    flush=True,
                )
            if args.halt_after_poke:
                halted_stop = "after-poke"
                halted_regs = gdb.registers()
            elif args.resume_checkpoint_script:
                (
                    linear_address,
                    field_name,
                    values,
                    observed_values,
                    max_hits,
                    input_events,
                ) = resumed_state_checkpoint_plan(
                    args.resume_checkpoint_script,
                    state_input_events,
                )
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
                            capture_screenshot=args.checkpoint_screenshot,
                        )
                        state_checkpoints.append(record)
                        print(
                            "captured resumed state checkpoint "
                            f"{field_name}={value} on hit {hit_index}",
                            flush=True,
                        )

                    def transition_resumed_script_keys(value: int) -> None:
                        for (
                            event_value,
                            pressed,
                            qcodes,
                        ) in input_events:
                            if event_value != value:
                                continue
                            ordered_qcodes = (
                                qcodes
                                if pressed
                                else list(reversed(qcodes))
                            )
                            for qcode in ordered_qcodes:
                                qmp_resume.key_event(qcode, pressed)
                            print(
                                f"key {'down' if pressed else 'up'} "
                                f"{'+'.join(qcodes)} at "
                                f"{field_name}={value}",
                                flush=True,
                            )

                    restored_regs = gdb.registers()
                    restored_state = read_resumed_checkpoint_state(
                        restored_regs
                    )
                    if restored_regs["eip"] != args.resume_next_linear:
                        raise ValueError(
                            "resume bootstrap stopped at the wrong next "
                            f"instruction: expected "
                            f"0x{args.resume_next_linear:05x}, observed "
                            f"0x{restored_regs['eip']:05x}"
                        )
                    first_value = observed_values[0]
                    if restored_state.get(field_name) != first_value:
                        raise ValueError(
                            "restored checkpoint state does not match "
                            f"{field_name}={first_value}: "
                            f"{restored_state.get(field_name)!r}"
                        )
                    capture_resumed_checkpoint(
                        first_value,
                        "resumed-state",
                        restored_regs,
                        restored_state,
                        0,
                    )
                    transition_resumed_script_keys(first_value)
                    if len(observed_values) == 1:
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
                            observed_values[1:],
                            max_hits,
                            args.timeout,
                            read_resumed_checkpoint_state,
                            capture_resumed_checkpoint,
                            transition_resumed_script_keys,
                            True,
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
                if (
                    args.post_resume_break_linear is not None
                    or post_resume_break_segmented is not None
                ):
                    if len(observed_values) > 1:
                        halted_stop = clear_halted_breakpoint(
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
                                capture_screenshot=args.checkpoint_screenshot,
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
                    if has_post_resume_next_break:
                        poke_writes = apply_halted_poke_files(
                            gdb,
                            args.post_resume_poke_file,
                            halted_regs,
                        )
                        for write in poke_writes:
                            print(
                                "post-resume poke-file wrote "
                                f"{write['size']} bytes from "
                                f"{write['path']} at "
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
                            next_description = (
                                f"{next_segment:04x}:{next_offset:04x}"
                            )
                            next_metadata = {
                                "segment": next_segment,
                                "offset": next_offset,
                                "hit_count": (
                                    args.post_resume_next_break_hit_count
                                ),
                            }
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
                            next_description = (
                                "0x"
                                f"{args.post_resume_next_break_linear:05x}"
                            )
                            next_metadata = {
                                "linear_address": (
                                    args.post_resume_next_break_linear
                                ),
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
                        print(
                            "stopped on post-resume next breakpoint hit "
                            f"{args.post_resume_next_break_hit_count} at "
                            f"{next_description}: {halted_stop}",
                            flush=True,
                        )
            else:
                gdb.continue_nowait()
                if args.post_restore_key:
                    qmp_post_restore = QmpClient(args.host, args.qmp_port, args.timeout)
                    try:
                        run_simple_key_actions(qmp_post_restore, args.post_restore_key)
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

        if args.vga_sequence_frames > 0:
            sequence_dir = args.out_dir / "vga_sequence"
            sequence_dir.mkdir(parents=True, exist_ok=True)
            sequence_rows: list[dict[str, Any]] = []
            previous_vga: bytes | None = None
            sequence_start = time.perf_counter()
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
                    frame_path = sequence_dir / f"frame_{index:04d}.bin"
                    frame_path.write_bytes(raw)
                    screen_path: Path | None = None
                    screenshot_error: str | None = None
                    if args.screenshot:
                        screen_path = sequence_dir / f"frame_{index:04d}.png"
                        screenshot_error = capture_optional_screenshot(
                            qmp_sequence,
                            screen_path,
                        )
                        if screenshot_error is not None:
                            screen_path = None
                            print(
                                f"sequence screenshot {index} skipped: "
                                f"{screenshot_error}",
                                flush=True,
                            )
                    sample_finished = time.perf_counter()
                    changed_pixels = (
                        0
                        if previous_vga is None
                        else sum(left != right for left, right in zip(previous_vga, raw))
                    )
                    frame_sha256 = hashlib.sha256(raw).hexdigest()
                    sequence_rows.append(
                        {
                            "index": index,
                            "scheduled_seconds": index * args.vga_sequence_interval,
                            "sample_started_seconds": sample_started - sequence_start,
                            "sample_finished_seconds": sample_finished - sequence_start,
                            "changed_pixels_from_previous": changed_pixels,
                            "sha256": frame_sha256,
                            "path": str(frame_path),
                            "screenshot": str(screen_path) if screen_path else None,
                            "screenshot_error": screenshot_error,
                        }
                    )
                    previous_vga = raw
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
                        "frames": sequence_rows,
                    },
                    indent=2,
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            print(f"wrote {sequence_manifest}", flush=True)

        stop = halted_stop
        regs = halted_regs
        if stop is None or regs is None:
            raise RuntimeError("internal error: final capture was not halted")
        qmp = QmpClient(args.host, args.qmp_port, args.timeout)
        dump_segment = regs[args.dump_segment]
        ds_linear = dump_segment << 4
        dump = qmp.memdump(ds_linear, args.dump_size)
        vga_dump = qmp.memdump(args.vga_address, vga_size)
        lowmem_dump = qmp.memdump(0x00000, 0xA0000) if args.dump_low_memory else None

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
        print(f"wrote {dump_path} ({len(dump)} bytes from linear 0x{ds_linear:05x})", flush=True)
        if lowmem_dump is not None:
            print(f"wrote {lowmem_path} ({len(lowmem_dump)} bytes from linear 0x00000)", flush=True)
        print(f"wrote {vga_pgm_path}", flush=True)
        if screenshot_path:
            print(f"wrote {screenshot_path}", flush=True)
        return 0
    finally:
        gdb.close()
        if "qmp" in locals():
            qmp.close()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"remote runtime dump failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
