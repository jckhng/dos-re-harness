"""Bounded, device-free 16-bit callback execution from a private RAM image."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping


@dataclass(frozen=True)
class CallbackResult:
    memory: bytes
    registers: dict[str, int]
    instructions: int


def run_callback(
    memory: bytes,
    registers: Mapping[str, int],
    *,
    entry: tuple[int, int],
    return_address: tuple[int, int],
    return_kind: str,
    max_instructions: int,
    timeout_us: int = 5_000_000,
) -> CallbackResult:
    """Run one near/far callback; fail on device access or missing return."""
    try:
        from unicorn import (
            Uc, UcError, UC_ARCH_X86, UC_MODE_16, UC_HOOK_CODE,
            UC_HOOK_INSN, UC_HOOK_INTR,
        )
        from unicorn import x86_const as x86
    except ImportError as error:
        raise ValueError("install optional dependency: unicorn==2.1.4") from error

    if not memory or len(memory) % 0x1000:
        raise ValueError("RAM image size must be nonzero and page-aligned")
    if return_kind not in ("near", "far"):
        raise ValueError("return_kind must be near or far")
    if return_kind == "near" and entry[0] != return_address[0]:
        raise ValueError("near return must stay in the entry code segment")
    if max_instructions < 1 or timeout_us < 1:
        raise ValueError("instruction and time caps must be positive")
    for name, address in (("entry", entry), ("return", return_address)):
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
    rejection = ""
    return_linear = (return_address[0] << 4) + return_address[1]

    def on_code(uc: Uc, address: int, size: int, user_data: object) -> None:
        nonlocal stopped, instructions
        if (address == return_linear and
                uc.reg_read(x86.UC_X86_REG_CS) == return_address[0] and
                uc.reg_read(x86.UC_X86_REG_IP) == return_address[1]):
            stopped = True
            uc.emu_stop()
            return
        instructions += 1

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

    cpu.hook_add(UC_HOOK_CODE, on_code)
    cpu.hook_add(UC_HOOK_INTR, reject_interrupt)
    cpu.hook_add(UC_HOOK_INSN, reject_io, None, 1, 0, x86.UC_X86_INS_IN)
    cpu.hook_add(UC_HOOK_INSN, reject_io, None, 1, 0, x86.UC_X86_INS_OUT)
    try:
        cpu.emu_start((entry[0] << 4) + entry[1], 0,
                      timeout=timeout_us, count=max_instructions)
    except UcError as error:
        raise ValueError(f"Unicorn stopped before callback return: {error}") from error
    if rejection:
        raise ValueError(rejection)
    if not stopped:
        raise ValueError("callback did not return within instruction limit or timeout")

    output = {name: cpu.reg_read(register_id) for name, register_id in register_ids.items()}
    output["ip"] = cpu.reg_read(x86.UC_X86_REG_IP)
    return CallbackResult(bytes(cpu.mem_read(0, len(memory))), output, instructions)
