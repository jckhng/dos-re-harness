"""RSP and QMP clients for the pinned DOSBox-X remote-debug protocol."""

from __future__ import annotations

import base64
import json
import math
import os
import select
import socket
import struct
import tempfile
import threading
import time
import zlib
from pathlib import Path
from typing import Any, Callable


_MAX_PIC_OBSERVER_EVENTS = 8192


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
        try:
            self.sock.settimeout(timeout)
            # ACK and next request are separate small writes; avoid Nagle delays.
            self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        except BaseException:
            self.sock.close()
            raise

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
                    checksum = bytearray()
                    while len(checksum) < 2:
                        fragment = self.sock.recv(2 - len(checksum))
                        if not fragment:
                            raise RuntimeError("GDB socket closed during checksum")
                        checksum.extend(fragment)
                    try:
                        expected = int(checksum, 16)
                    except ValueError as exc:
                        raise RuntimeError("GDB packet has an invalid checksum") from exc
                    if expected != sum(data) & 0xff:
                        self.sock.sendall(b"-")
                        raise RuntimeError("GDB packet checksum mismatch")
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
        breakpoints = getattr(self, "_software_breakpoints", set())
        key = (linear_address, kind)
        if key in breakpoints:
            return
        response = self.packet(f"Z0,{linear_address:x},{kind:x}")
        if response != "OK":
            raise RuntimeError(
                "GDB software breakpoint insertion failed at "
                f"0x{linear_address:x}: {response!r}"
            )
        # Some backends add duplicate traps but remove only one per packet.
        breakpoints.add(key)
        self._software_breakpoints = breakpoints

    def remove_breakpoint(self, linear_address: int, kind: int = 1) -> None:
        response = self.packet(f"z0,{linear_address:x},{kind:x}")
        if response != "OK":
            raise RuntimeError(
                "GDB software breakpoint removal failed at "
                f"0x{linear_address:x}: {response!r}"
            )
        getattr(self, "_software_breakpoints", set()).discard((linear_address, kind))

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
        current_ip = current["eip"] - ((current["cs"] & 0xFFFF) << 4)
        if 0 <= current_ip <= 0xFFFF:
            current["eip"] = current_ip
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



def _valid_cpu_timing(timing: Any) -> bool:
    if not isinstance(timing, dict) or not timing:
        return False
    for key, value in timing.items():
        if key == "pic_events":
            if not isinstance(value, list) or len(value) > _MAX_PIC_OBSERVER_EVENTS:
                return False
            previous = -math.inf
            for event in value:
                if not isinstance(event, dict) or set(event) != {"tick_index", "handler", "value"}:
                    return False
                index = event["tick_index"]
                if (isinstance(index, bool) or not isinstance(index, (int, float))
                        or not math.isfinite(index) or index < previous):
                    return False
                if type(event["handler"]) is not int or not 0 <= event["handler"] < (1 << 16):
                    return False
                if type(event["value"]) is not int or not 0 <= event["value"] < (1 << 64):
                    return False
                previous = index
            continue
        if type(value) is not int:
            return False
        if key in ("remaining_cycles", "deferred_cycles"):
            if not -(1 << 63) <= value < (1 << 63):
                return False
        elif not 0 <= value < (1 << 64):
            return False
    return True



class QmpClient:
    _memory_fallback: Callable[[int, int], bytes] | None = None

    @classmethod
    def set_memory_fallback(
        cls,
        reader: Callable[[int, int], bytes] | None,
    ) -> None:
        cls._memory_fallback = reader

    def set_memory_reader(self, reader: Callable[[int, int], bytes] | None) -> None:
        """Override the legacy fallback for this connection, including disabling it."""
        self._memory_reader = reader

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
        try:
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
        except BaseException:
            self.sock.close()
            raise

    def close(self) -> None:
        self.sock.close()

    def _recv_json(self) -> dict[str, Any]:
        data = getattr(self, "_receive_buffer", b"")
        previous_timeout = self.sock.gettimeout()
        deadline = None if previous_timeout is None else time.monotonic() + previous_timeout
        decoder = json.JSONDecoder()
        try:
            while True:
                data = data.lstrip()
                try:
                    decoded = data.decode("utf-8")
                except UnicodeDecodeError as exc:
                    if exc.reason != "unexpected end of data":
                        raise RuntimeError("QMP returned invalid UTF-8") from exc
                    decoded = data[:exc.start].decode("utf-8")
                try:
                    value, end = decoder.raw_decode(decoded)
                except json.JSONDecodeError:
                    pass
                else:
                    if not isinstance(value, dict):
                        raise RuntimeError("QMP message must be an object")
                    self._receive_buffer = data[len(decoded[:end].encode("utf-8")):]
                    return value
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("QMP response deadline exceeded")
                    self.sock.settimeout(remaining)
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise RuntimeError("QMP socket closed")
                data += chunk
        finally:
            self.sock.settimeout(previous_timeout)

    def command(
        self,
        execute: str,
        arguments: dict[str, Any] | None = None,
        timeout: float | None = None,
        sent_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        if getattr(self, "_unusable", False):
            raise RuntimeError("QMP connection is unusable after a transport failure; open a new connection")
        msg: dict[str, Any] = {"execute": execute}
        if arguments is not None:
            msg["arguments"] = arguments
        previous_timeout = self.sock.gettimeout()
        if timeout is not None:
            self.sock.settimeout(timeout)
        request_timeout = self.sock.gettimeout()
        deadline = None if request_timeout is None else time.monotonic() + request_timeout
        try:
            self.sock.sendall((json.dumps(msg) + "\n").encode("utf-8"))
            if sent_event is not None:
                sent_event.set()
            while True:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("QMP response deadline exceeded")
                    self.sock.settimeout(remaining)
                response = self._recv_json()
                if "event" not in response:
                    break
            if "return" not in response and "error" not in response:
                raise RuntimeError("QMP response has neither return nor error")
        except (OSError, RuntimeError):
            # A late response cannot safely be assigned to the next request.
            self._unusable = True
            raise
        finally:
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
            shared_directory = os.environ.get("DOS_RE_HARNESS_QMP_TEMP_DIRECTORY")
            if shared_directory:
                return self._memdump_file(address, size, shared_directory)
            response = self.command(
                "memdump",
                {"address": address, "size": size},
            )
        except (TimeoutError, socket.timeout):
            fallback = getattr(self, "_memory_reader", type(self)._memory_fallback)
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
        data = base64.b64decode(payload)
        if len(data) != size:
            raise RuntimeError(f"QMP memory dump returned an unexpected size: {len(data)} (expected {size})")
        return data

    def _memdump_file(self, address: int, size: int, directory: str) -> bytes:
        # Explicit shared host directory: backend and controller must see the same path.
        with tempfile.TemporaryDirectory(prefix="dos-re-memdump-", dir=directory) as temporary:
            path = Path(temporary) / "memory.bin"
            response = self.command("memdump", {"address": address, "size": size, "file": str(path)})
            if response.get("return", {}).get("file") != str(path):
                raise RuntimeError(f"QMP memory dump returned an unexpected path: {response}")
            data = path.read_bytes()
            if len(data) != size:
                raise RuntimeError(f"QMP memory dump returned an unexpected size: {len(data)} (expected {size})")
            return data

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
        timing_metadata = {}
        if "video_timing" in result:
            timing = result["video_timing"]
            if not isinstance(timing, dict) or not timing or any(
                isinstance(value, bool)
                or not isinstance(value, (int, float))
                or not math.isfinite(value)
                for value in timing.values()
            ):
                raise RuntimeError("QMP dacdump returned invalid video timing")
            timing_metadata["video_timing"] = timing
        if "cpu_timing" in result:
            timing = result["cpu_timing"]
            if not _valid_cpu_timing(timing):
                raise RuntimeError("QMP dacdump returned invalid CPU timing")
            timing_metadata["cpu_timing"] = timing
        return {
            "data": data,
            **timing_metadata,
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
