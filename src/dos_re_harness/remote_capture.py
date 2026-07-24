#!/usr/bin/env python3
"""Control a remotedebug DOSBox-X instance and capture runtime evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import socket
import struct
import sys
import time
from pathlib import Path
from typing import Any

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

    def halt(self, timeout: float) -> str:
        self.sock.sendall(b"\x03")
        return self._recv_packet(timeout)

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

    def write_memory_chunked(self, address: int, data: bytes, chunk_size: int = 4096) -> None:
        for offset in range(0, len(data), chunk_size):
            self.write_memory(address + offset, data[offset : offset + chunk_size])


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
            "Startup action; repeatable. Supports wait:<s>, waitvga:<state>:<s>, "
            "waitnotvga:<state>:<s>, drivevga:<state>:<timeout>:<qcode>[:hold][:interval], "
            "hold:<qcode>:<s>, tap:<qcode>[:s], keydown:<qcode>, keyup:<qcode>, "
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
    parser.add_argument("--dump-low-memory", action="store_true",
                        help="Also dump conventional memory 0x00000..0x9ffff for snapshot restore")
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
    args = parser.parse_args()
    wait_predicates = [parse_state_predicate(spec) for spec in args.wait_state]
    state_fields = load_schema(args.state_schema) if args.state_schema else []
    screen_classifier = (
        ScreenClassifier.load(args.screen_signatures)
        if args.screen_signatures
        else None
    )
    if wait_predicates and not state_fields:
        parser.error("--wait-state requires --state-schema")
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
        initial = gdb.packet("?")
        if initial.startswith(("S", "T")):
            # The remotedebug fork starts halted when a GDB client is attached.
            gdb.sock.sendall(b"$c#63")
            ack = gdb.sock.recv(1)
            if ack != b"+":
                raise RuntimeError(f"unexpected continue ACK: {ack!r}")

        args.out_dir.mkdir(parents=True, exist_ok=True)
        (args.out_dir / "remote_runtime_args.json").write_text(
            json.dumps(
                {
                    "startup_key": args.startup_key,
                    "wait_state": args.wait_state,
                    "vga_sequence_frames": args.vga_sequence_frames,
                    "vga_sequence_interval": args.vga_sequence_interval,
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
                        _, state, timeout_s = key.split(":", 2)
                        deadline = time.time() + float(timeout_s)
                        last_state = "unknown"
                        last_raw = b""
                        while time.time() < deadline:
                            last_raw = qmp_startup.memdump(args.vga_address, vga_size)
                            last_state = classify_frame(last_raw)
                            if last_state == state:
                                break
                            time.sleep(0.5)
                        else:
                            timeout_path = args.out_dir / f"waitvga_timeout_{state}.bin"
                            timeout_pgm_path = args.out_dir / f"waitvga_timeout_{state}.pgm"
                            timeout_path.write_bytes(last_raw)
                            timeout_pgm_path.write_bytes(pgm_header + last_raw)
                            raise RuntimeError(f"timed out waiting for VGA state {state!r}; last={last_state!r}")
                        print(f"waitvga matched {state}", flush=True)
                        continue
                    if key.startswith("waitnotvga:"):
                        _, state, timeout_s = key.split(":", 2)
                        deadline = time.time() + float(timeout_s)
                        last_state = "unknown"
                        last_raw = b""
                        while time.time() < deadline:
                            last_raw = qmp_startup.memdump(args.vga_address, vga_size)
                            last_state = classify_frame(last_raw)
                            if last_state != state:
                                break
                            time.sleep(0.5)
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
        if args.poke or args.poke_file or args.restore_registers or args.call_near is not None:
            stop = gdb.halt(args.timeout)
            regs = gdb.registers()
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
                gdb.write_registers({str(k): int(v) for k, v in registers.items()})
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
                    screen_path: Path | None = None
                    if args.screenshot:
                        screen_path = sequence_dir / f"frame_{index:04d}.png"
                        screen_path.write_bytes(qmp_sequence.screendump())
                    sample_finished = time.perf_counter()
                    frame_path = sequence_dir / f"frame_{index:04d}.bin"
                    frame_path.write_bytes(raw)
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
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

        print(f"halt stop: {stop}", flush=True)
        print(
            "registers: "
            f"cs={regs['cs']:04x} eip={regs['eip']:08x} "
            f"ds={regs['ds']:04x} ss={regs['ss']:04x} sp={regs['esp'] & 0xffff:04x}",
            flush=True,
        )
        print(f"wrote {regs_path}", flush=True)
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
