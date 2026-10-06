"""Recover the value a register holds just before the next call.

Used for rule meta ``<name>_size_reg``: the length of a data blob is usually passed in an
argument register as an immediate (``MOV R2, #0x14A`` ... ``BL add_entry``).
Supported: ARM (A32) MOV/MVN/ADD/SUB/ORR with immediates, MOVW/MOVT; MIPS32 addiu/ori/lui (delay slot included).
"""
from __future__ import annotations

import re

from .formats.base import Image


def _arm_imm(w: int) -> int:
    imm, rot = w & 0xFF, ((w >> 8) & 0xF) * 2
    if rot == 0:
        return imm
    return ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF


def _arm_reg(reg: str) -> int:
    m = re.fullmatch(r"[rR](\d{1,2})", reg.strip())
    if not m or int(m.group(1)) > 15:
        raise ValueError(f"unknown ARM register {reg!r} (use r0..r15)")
    return int(m.group(1))


def _recover_arm(read, at: int, reg: str, window: int):
    target = _arm_reg(reg)
    code = read(at, window)
    value = None
    for pos in range(0, len(code) - 3, 4):
        w = int.from_bytes(code[pos:pos + 4], "little")
        if (w & 0x0F000000) == 0x0B000000 and (w >> 28) != 0xF:      # BL: the call we are looking for
            return value if value else None
        rd, rn = (w >> 12) & 0xF, (w >> 16) & 0xF

        if (w & 0x0FF00000) == 0x03000000:                              # MOVW
            if rd == target:
                value = ((w >> 4) & 0xF000) | (w & 0xFFF)
            continue
        if (w & 0x0FF00000) == 0x03400000:                              # MOVT
            if rd == target:
                value = None if value is None else (value & 0xFFFF) | ((((w >> 4) & 0xF000) | (w & 0xFFF)) << 16)
            continue
        cls = (w >> 26) & 3
        if cls == 0 and (w >> 25) & 1:                                  # data processing, immediate
            if rd != target:
                continue
            op, imm = (w >> 21) & 0xF, _arm_imm(w)
            if op == 13:                                                # MOV
                value = imm
            elif op == 15:                                              # MVN
                value = ~imm & 0xFFFFFFFF
            elif rn == target and value is not None and op in (4, 2, 12):   # ADD / SUB / ORR
                value = ((value + imm) if op == 4 else (value - imm) if op == 2 else (value | imm)) & 0xFFFFFFFF
            elif op not in (8, 9, 10, 11):                              # not a compare: register is clobbered
                value = None
        elif cls == 0:                                                  # data processing, register form
            if rd == target and not 8 <= ((w >> 21) & 0xF) <= 11:
                value = None
        elif cls == 1 and (w >> 20) & 1 and rd == target:               # LDR/LDRB into the register
            value = None
    return None


_MIPS_REGS = {"zero": 0, "at": 1, "v0": 2, "v1": 3, "a0": 4, "a1": 5, "a2": 6, "a3": 7,
              **{f"t{i}": 8 + i for i in range(8)}, **{f"s{i}": 16 + i for i in range(8)},
              "t8": 24, "t9": 25, "k0": 26, "k1": 27, "gp": 28, "sp": 29, "fp": 30, "s8": 30, "ra": 31}


def _mips_reg(reg: str) -> int:
    r = reg.strip().lstrip("$").lower()
    if r in _MIPS_REGS:
        return _MIPS_REGS[r]
    m = re.fullmatch(r"r(\d{1,2})", r)
    if m and int(m.group(1)) < 32:
        return int(m.group(1))
    raise ValueError(
        f"unknown MIPS register {reg!r}: name the register that carries the length "
        f"(\"a2\" for `li $a2, N`), not the instruction")


def mips_dest(w: int):
    """Register written by a MIPS instruction word, or None (stores, branches, jr, hi/lo ops ...)."""
    opc = w >> 26
    if opc == 0:
        if (w & 0x3F) in (0x08, 0x0C, 0x0D, 0x11, 0x13, 0x18, 0x19, 0x1A, 0x1B):
            return None
        return (w >> 11) & 31                       # rd (jalr: the link register)
    if 0x08 <= opc <= 0x0F or 0x20 <= opc <= 0x26:
        return (w >> 16) & 31                       # rt: addi/andi/ori/lui/loads ...
    if opc == 0x03:
        return 31                                   # jal
    return None


def _recover_mips(read, at: int, reg: str, window: int, order: str):
    """Value of ``reg`` at the next call, delay slot included (the compiler often puts
    ``li $a2, N`` after the ``jalr``/``jal``)."""
    target = _mips_reg(reg)
    code = read(at, window)
    value = None
    after_call = False
    for pos in range(0, len(code) - 3, 4):
        w = int.from_bytes(code[pos:pos + 4], order)
        opc, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        if opc == 0x09 and rt == target:                                    # addiu
            if rs == 0:
                value = simm & 0xFFFFFFFF
            elif rs == target and value is not None:
                value = (value + simm) & 0xFFFFFFFF
            else:
                value = None
        elif opc == 0x0D and rt == target:                                  # ori
            if rs == 0:
                value = imm
            elif rs == target and value is not None:
                value |= imm
            else:
                value = None
        elif opc == 0x0F and rt == target:                                  # lui
            value = (imm << 16) & 0xFFFFFFFF
        elif mips_dest(w) == target:
            value = None
        if after_call:
            return value if value else None
        if opc == 0x03 or (opc == 0 and (w & 0x3F) in (0x08, 0x09)):        # jal / jr / jalr
            after_call = True
    return None


def recover_register(image: Image, read, at: int, reg: str, window: int = 64):
    """Value of ``reg`` at the first call (BL) after the instruction at file offset ``at``,
    or None.  Raises ValueError when the architecture is unsupported."""
    if image.arch == "arm":
        return _recover_arm(read, at, reg, window)
    if image.arch == "mips":
        return _recover_mips(read, at, reg, window, image.endian)
    raise ValueError(f"size_reg is not supported for {image.arch or 'unknown'} binaries yet (ARM and MIPS only)")
