"""Bounded, device-free 16-bit callback execution from a private RAM image."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

_PAGE_BYTES = 0x1000


@dataclass(frozen=True)
class CallbackObservation:
    instruction: int
    registers: dict[str, int]


@dataclass(frozen=True)
class MemoryWrite:
    sequence: int
    instruction: int
    cs: int
    ip: int
    address: int
    before: bytes
    written: bytes


@dataclass(frozen=True)
class CallbackResult:
    memory: bytes
    registers: dict[str, int]
    instructions: int
    observations: tuple[CallbackObservation, ...] = ()
    writes: tuple[MemoryWrite, ...] = ()


def run_callback(
    memory: bytes,
    registers: Mapping[str, int],
    *,
    entry: tuple[int, int],
    return_address: tuple[int, int],
    return_kind: str,
    max_instructions: int,
    timeout_us: int = 5_000_000,
    observe_addresses: tuple[tuple[int, int], ...] = (),
    stop_hit_count: int = 1,
    write_ranges: tuple[tuple[int, int], ...] = (),
    max_writes: int = 4096,
) -> CallbackResult:
    """Run a callback or stack-preserving snapshot to a device-free stop."""
    try:
        from unicorn import (
            Uc, UcError, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
            UC_HOOK_INSN, UC_HOOK_INTR,
            UC_HOOK_MEM_INVALID, UC_MEM_READ_UNMAPPED, UC_MEM_WRITE_UNMAPPED,
            UC_MEM_FETCH_UNMAPPED, UC_HOOK_MEM_WRITE,
        )
        from unicorn import x86_const as x86
    except ImportError as error:
        raise ValueError("install optional dependency: unicorn==2.1.4") from error

    if not memory or len(memory) % _PAGE_BYTES:
        raise ValueError("RAM image size must be nonzero and page-aligned")
    if return_kind not in ("near", "far", "snapshot"):
        raise ValueError("return_kind must be near, far or snapshot")
    if return_kind == "near" and entry[0] != return_address[0]:
        raise ValueError("near return must stay in the entry code segment")
    if max_instructions < 1 or timeout_us < 1:
        raise ValueError("instruction and time caps must be positive")
    if stop_hit_count < 1 or (stop_hit_count != 1 and return_kind != "snapshot"):
        raise ValueError("stop hit count must be positive; repeated stops require snapshot mode")
    if type(max_writes) is not int or max_writes < 1:
        raise ValueError("max_writes must be a positive integer")
    for start, end in write_ranges:
        if type(start) is not int or type(end) is not int or not 0 <= start < end <= len(memory):
            raise ValueError("write ranges must be nonempty half-open RAM intervals")
    for name, address in (("entry", entry), ("return", return_address),
            *(("observation", address) for address in observe_addresses)):
        if any(not 0 <= value <= 0xFFFF for value in address):
            raise ValueError(f"{name} is not a real-mode segment:offset")
        if (address[0] << 4) + address[1] >= len(memory):
            raise ValueError(f"{name} lies outside the RAM image")

    cpu = Uc(UC_ARCH_X86, UC_MODE_16)
    cpu.mem_map(0, len(memory))
    cpu.mem_write(0, memory)
    register_ids = {
        "ax": x86.UC_X86_REG_AX, "bx": x86.UC_X86_REG_BX,
        "cx": x86.UC_X86_REG_CX, "dx": x86.UC_X86_REG_DX,
        "si": x86.UC_X86_REG_SI, "di": x86.UC_X86_REG_DI,
        "bp": x86.UC_X86_REG_BP, "sp": x86.UC_X86_REG_SP,
        "cs": x86.UC_X86_REG_CS, "ds": x86.UC_X86_REG_DS,
        "ss": x86.UC_X86_REG_SS, "es": x86.UC_X86_REG_ES,
        "fs": x86.UC_X86_REG_FS, "gs": x86.UC_X86_REG_GS,
        "flags": x86.UC_X86_REG_EFLAGS,
    }
    for name, register_id in register_ids.items():
        source = "eflags" if name == "flags" else "e" + name if name in (
            "ax", "bx", "cx", "dx", "si", "di", "bp", "sp"
        ) else name
        value = registers.get(source, registers.get(name, 0))
        cpu.reg_write(register_id, value if name == "flags" else value & 0xFFFF)
    cpu.reg_write(x86.UC_X86_REG_CS, entry[0])

    if return_kind != "snapshot":
        stack_bytes = 4 if return_kind == "far" else 2
        sp = (cpu.reg_read(x86.UC_X86_REG_SP) - stack_bytes) & 0xFFFF
        ss = cpu.reg_read(x86.UC_X86_REG_SS)
        stack_linear = (ss << 4) + sp
        if stack_linear + stack_bytes > len(memory):
            raise ValueError("synthetic return stack lies outside the RAM image")
        cpu.reg_write(x86.UC_X86_REG_SP, sp)
        cpu.mem_write(stack_linear, return_address[1].to_bytes(2, "little"))
        if return_kind == "far":
            cpu.mem_write(stack_linear + 2, return_address[0].to_bytes(2, "little"))

    stopped = False
    instructions = 0
    stop_hits = 0
    rejection = ""
    memory_fault = ""
    return_linear = (return_address[0] << 4) + return_address[1]
    observed = set(observe_addresses)
    observed_linear = {(segment << 4) + offset for segment, offset in observed}
    observations: list[CallbackObservation] = []
    writes: list[MemoryWrite] = []
    executed_pages: set[int] = set()

    def read_registers() -> dict[str, int]:
        result = {name: cpu.reg_read(register_id) for name, register_id in register_ids.items()}
        result["ip"] = cpu.reg_read(x86.UC_X86_REG_IP)
        return result

    def on_code(uc: Uc, address: int, size: int, user_data: object) -> None:
        nonlocal stopped, instructions, stop_hits
        if (address == return_linear and
                uc.reg_read(x86.UC_X86_REG_CS) == return_address[0] and
                uc.reg_read(x86.UC_X86_REG_IP) == return_address[1]):
            stop_hits += 1
            if stop_hits == stop_hit_count:
                stopped = True
                uc.emu_stop()
                return
        instructions += 1
        if write_ranges:
            executed_pages.update(range(address // _PAGE_BYTES, (address + size - 1) // _PAGE_BYTES + 1))
        if address in observed_linear and (
                uc.reg_read(x86.UC_X86_REG_CS), uc.reg_read(x86.UC_X86_REG_IP)) in observed:
            observations.append(CallbackObservation(instructions, read_registers()))

    def reject_interrupt(uc: Uc, number: int, user_data: object) -> None:
        nonlocal rejection
        cs = uc.reg_read(x86.UC_X86_REG_CS)
        ip = uc.reg_read(x86.UC_X86_REG_IP)
        ah = uc.reg_read(x86.UC_X86_REG_AH)
        rejection = (f"interrupt {number:#x} at {cs:04x}:{ip:04x} "
                     f"AH={ah:02x} requires DOS/device emulation")
        uc.emu_stop()

    def reject_io(uc: Uc, *args: object) -> int:
        nonlocal rejection
        rejection = "port I/O requires device emulation"
        uc.emu_stop()
        return 0

    def reject_memory(uc: Uc, access: int, address: int, size: int, value: int, user_data: object) -> bool:
        nonlocal memory_fault
        kind = {UC_MEM_READ_UNMAPPED: "read", UC_MEM_WRITE_UNMAPPED: "write",
            UC_MEM_FETCH_UNMAPPED: "fetch"}.get(access)
        operation = f"unmapped {kind}" if kind is not None else f"invalid memory access {access}"
        cs, ip = uc.reg_read(x86.UC_X86_REG_CS), uc.reg_read(x86.UC_X86_REG_IP)
        memory_fault = f"{operation} at {address:#x} size={size} from {cs:04x}:{ip:04x}"
        return False

    def on_write(uc: Uc, access: int, address: int, size: int, value: int, user_data: object) -> None:
        nonlocal rejection
        # Code-page writes can trigger retried pre-write hooks during translation.
        if any(page in executed_pages for page in range(address // _PAGE_BYTES, (address + size - 1) // _PAGE_BYTES + 1)):
            rejection = "memory-write trace rejects writes to executed code pages"
            uc.emu_stop()
            return
        if not any(address < end and address + size > start for start, end in write_ranges):
            return
        if len(writes) >= max_writes:
            rejection = "memory-write trace exceeded max_writes"
            uc.emu_stop()
            return
        if address < 0 or address + size > len(memory) or size > 8:
            rejection = "memory-write trace encountered unsupported access"
            uc.emu_stop()
            return
        writes.append(MemoryWrite(len(writes) + 1, instructions,
            uc.reg_read(x86.UC_X86_REG_CS), uc.reg_read(x86.UC_X86_REG_IP),
            address, bytes(uc.mem_read(address, size)),
            (value & ((1 << (size * 8)) - 1)).to_bytes(size, "little")))

    cpu.hook_add(UC_HOOK_CODE, on_code)
    cpu.hook_add(UC_HOOK_INTR, reject_interrupt)
    cpu.hook_add(UC_HOOK_MEM_INVALID, reject_memory)
    cpu.hook_add(UC_HOOK_INSN, reject_io, None, 1, 0, x86.UC_X86_INS_IN)
    cpu.hook_add(UC_HOOK_INSN, reject_io, None, 1, 0, x86.UC_X86_INS_OUT)
    if write_ranges:
        cpu.hook_add(UC_HOOK_MEM_WRITE, on_write)
    try:
        cpu.emu_start((entry[0] << 4) + entry[1], 0,
                      timeout=timeout_us, count=max_instructions)
    except UcError as error:
        raise ValueError(f"Unicorn stopped before callback return: {memory_fault or error}") from error
    if rejection:
        raise ValueError(rejection)
    if not stopped:
        raise ValueError("callback did not return within instruction limit or timeout")

    return CallbackResult(bytes(cpu.mem_read(0, len(memory))), read_registers(), instructions,
                          tuple(observations), tuple(writes))
