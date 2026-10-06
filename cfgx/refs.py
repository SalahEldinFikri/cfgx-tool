"""Follow code references (``lea rax,[rip+x]``, ``push 0x405000`` ...) to the
data they point at.

A YARA rule usually matches a few instructions that load the address of the
config or the key.  ``find_references`` turns those instruction bytes into
file offsets.  Support is per architecture; unsupported architectures simply
return no references (the engine then falls back to the match location).
"""
from __future__ import annotations

from typing import Callable, Dict, List

from .consts import mips_dest
from .formats.base import Image

Reference = Dict[str, object]


def _make(image: Image, va: int, at: int, kind: str):
    """A reference to ``va``.  If the address is mapped in memory but has no bytes in the file
    (.bss, zero-initialised tails) the reference is kept as a placeholder with ``offset = None``,
    so ``ref_index`` always counts the address-loading instructions of the match the same way."""
    offset = image.va_to_offset(va)
    if offset is None and image.mapping_at_va(va) is None:
        return None                                   # not an address of this image at all
    return {
        "offset": offset,
        "rva": va - image.image_base,
        "va": va,
        "kind": kind,
        "at": at,          # file offset of the instruction that referenced it
    }


def _x64(image: Image, base: int, data: bytes, read=None) -> List[Reference]:
    refs: List[Reference] = []
    n = len(data)
    for p in range(n):
        b = data[p]
        # opcode [+ modrm] + disp32, no immediate -> instruction ends right after disp32
        if b in (0x8D, 0x8B):                     # lea / mov r, [rip+x]
            modrm_i, length = p + 1, 6
            kind = "lea" if b == 0x8D else "mov"
        elif b == 0x0F and p + 1 < n and data[p + 1] in (0xB6, 0xB7, 0xBE, 0xBF):
            modrm_i, length = p + 2, 7             # movzx / movsx
            kind = "movzx"
        elif b in (0x48, 0x49) and p + 1 < n and 0xB8 <= data[p + 1] <= 0xBF:
            # movabs reg, imm64 (absolute address)
            if p + 10 > n:
                continue
            va = int.from_bytes(data[p + 2:p + 10], "little")
            ref = _make(image, va, base + p, "movabs")
            if ref:
                refs.append(ref)
            continue
        else:
            continue

        if p + length > n or (data[modrm_i] & 0xC7) != 0x05:
            continue
        op_va = image.offset_to_va(base + p)
        if op_va is None:
            continue
        disp = int.from_bytes(data[modrm_i + 1:modrm_i + 5], "little", signed=True)
        ref = _make(image, op_va + length + disp, base + p, kind)
        if ref:
            refs.append(ref)
    return refs


def _x86(image: Image, base: int, data: bytes, read=None) -> List[Reference]:
    refs: List[Reference] = []
    n = len(data)
    for p in range(n):
        b = data[p]
        if b == 0x68 and p + 5 <= n:                          # push imm32
            va, kind = int.from_bytes(data[p + 1:p + 5], "little"), "push"
        elif 0xB8 <= b <= 0xBF and p + 5 <= n:                # mov r32, imm32
            va, kind = int.from_bytes(data[p + 1:p + 5], "little"), "mov"
        elif b == 0x8D and p + 6 <= n and (data[p + 1] & 0xC7) == 0x05:   # lea r,[abs32]
            va, kind = int.from_bytes(data[p + 2:p + 6], "little"), "lea"
        elif b == 0x8B and p + 6 <= n and (data[p + 1] & 0xC7) == 0x05:   # mov r,[abs32]  (a variable)
            va, kind = int.from_bytes(data[p + 2:p + 6], "little"), "mov-mem"
        elif b == 0xA1 and p + 5 <= n:                                    # mov eax,[moffs32]
            va, kind = int.from_bytes(data[p + 1:p + 5], "little"), "mov-mem"
        else:
            continue
        ref = _make(image, va, base + p, kind)
        if ref:
            refs.append(ref)
    return refs


def _arm(image: Image, base: int, data: bytes, read=None) -> List[Reference]:
    """ARM (A32) ``LDR Rd, =label``: ``ldr rd, [pc, #+/-imm12]`` loads a pointer from the
    literal pool; the pointer is the reference.  Needs ``read`` to fetch the pool word."""
    refs: List[Reference] = []
    if read is None:
        return refs
    for p in range(0, len(data) - 3):
        op_va = image.offset_to_va(base + p)
        if op_va is None or op_va & 3:                 # A32 instructions are 4-byte aligned
            continue
        w = int.from_bytes(data[p:p + 4], "little")
        if (w >> 28) == 0xF:                           # unconditional space, not an LDR
            continue
        if (w & 0x0F7F0000) != 0x051F0000:             # LDR (word) immediate, Rn=PC, P=1,B=0,W=0
            continue
        imm = w & 0xFFF
        pool_va = op_va + 8 + (imm if (w >> 23) & 1 else -imm)
        pool_off = image.va_to_offset(pool_va)
        if pool_off is None:
            continue
        word = read(pool_off, 4)
        if len(word) != 4:
            continue
        ref = _make(image, int.from_bytes(word, "little"), base + p, "ldr")
        if ref:
            refs.append(ref)
    return refs


def _mips(image: Image, base: int, data: bytes, read=None) -> List[Reference]:
    """MIPS32 addresses.  A tiny register tracker follows, in order, the instructions *before and
    inside* the match, so all the usual ways to form an address work:

    * ``lui rt,hi`` + ``addiu``/``ori``                       (non-PIC)
    * ``lw rt, imm($gp)`` (GOT entry; needs ``image.gp``)      (PIC: ``la rt, symbol``)
    * ``lw $v0, imm($gp)`` *before* the match, then ``addiu $a1,$v0,off`` inside it (symbol + offset)

    A reference is reported for the instruction inside the match that produced the address."""
    refs: List[Reference] = []
    order = image.endian
    window, start = data, base
    if read is not None:                                  # a few instructions of context before the match
        m = image.mapping_at_offset(base)
        back = min(32, base - m.file_offset) if m else 0
        back -= back % 4
        if back:
            prefix = read(base - back, back)
            if len(prefix) == back:
                window, start = prefix + data, base - back

    regs: Dict[int, object] = {}                          # register -> (value, origin) or None (unknown)

    def source(r):
        return (0, "const") if r == 0 else regs.get(r)

    for p in range(0, len(window) - 3):
        f = start + p
        op_va = image.offset_to_va(f)
        if op_va is None or op_va & 3:
            continue
        w = int.from_bytes(window[p:p + 4], order)
        opc, rs, rt, imm = w >> 26, (w >> 21) & 31, (w >> 16) & 31, w & 0xFFFF
        simm = imm - 0x10000 if imm & 0x8000 else imm
        inside = f >= base

        if opc == 0x0F:                                                   # lui
            regs[rt] = ((imm << 16) & 0xFFFFFFFF, "lui")
        elif opc in (0x09, 0x0D):                                         # addiu / ori
            src = source(rs)
            if src is None:
                regs[rt] = None
                continue
            value = ((src[0] + simm) & 0xFFFFFFFF) if opc == 0x09 else (src[0] | imm)
            regs[rt] = (value, src[1])
            if rs and inside and src[1] != "const":
                kind = {"lui": "lui+", "gp": "gp+"}.get(src[1], "") + ("addiu" if opc == 0x09 else "ori")
                ref = _make(image, value, f, kind)
                if ref:
                    refs.append(ref)
        elif opc == 0x23:                                                 # lw
            regs[rt] = None
            if rs == 28 and image.gp is not None and read is not None:    # lw rt, imm($gp): a GOT entry
                pool = image.va_to_offset((image.gp + simm) & 0xFFFFFFFF)
                word = read(pool, 4) if pool is not None else b""
                if len(word) == 4:
                    value = int.from_bytes(word, order)
                    regs[rt] = (value, "gp")
                    if inside:
                        ref = _make(image, value, f, "gp-got")
                        if ref:
                            refs.append(ref)
        else:
            dest = mips_dest(w)
            if dest is not None:
                regs[dest] = None
    return refs


RESOLVERS: Dict[str, Callable[..., List[Reference]]] = {
    "x64": _x64,
    "x86": _x86,
    "arm": _arm,
    "mips": _mips,
    # "arm64": add an ADRP+ADD resolver here
}


def find_references(image: Image, match_offset: int, match_data: bytes, read=None) -> List[Reference]:
    """All distinct data references found inside the matched instruction bytes,
    in the order they appear.  ``read(offset, size)`` is only needed for ARM literal pools."""
    resolver = RESOLVERS.get(image.arch or "")
    if resolver is None:
        return []
    seen = set()
    unique: List[Reference] = []
    for ref in resolver(image, match_offset, match_data, read):
        key = (ref["offset"], ref["va"])
        if key in seen:
            continue
        seen.add(key)
        unique.append(ref)
    return unique
