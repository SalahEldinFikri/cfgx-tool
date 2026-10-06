"""Synthetic Vulcan (Go) implants for x86 / amd64 / ARM5 / ARM7 / MIPS / MIPSLE, built from the
byte patterns in examples/vulcan/rule.yar."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_elf32, build_elf64, rip_disp  # noqa: E402

C2 = b"146.19.213.198:8443"           # 0x13 = 19 bytes
ARCHS = ["386", "amd64", "arm5", "arm7", "mips", "mipsle"]
EXPECTED_RULE = {"386": "version_386_elf", "amd64": "version_amd64", "arm5": "version_arm5",
                 "arm7": "version_arm7", "mips": "version_mips", "mipsle": "version_mipsle"}

MARKERS = [b"vulcan_386", b"vulcan-agent", b"vulcan/implant"]
DEBUG = [b"[DEBUG] Dial error: %v\n", b"[DEBUG] Read error: %v\n", b"[DEBUG] readLoop started",
         b"[DEBUG] Write error: %v\n", b"[DEBUG] Scanning enabled", b"[DEBUG] Invalid URL: %v\n",
         b"[DEBUG] Implant starting...insufficient security level", b'GODEBUG sys/cpu: value "',
         b'GODEBUG: can not enable "', b'GODEBUG: unknown cpu feature "', b'GODEBUG: no value specified for "']


def rdata(with_c2=True):
    """Go keeps strings in one blob with no NULs between them."""
    blob = b"\x00".join(MARKERS + DEBUG) + b"\x00"
    start = len(blob)
    if with_c2:
        blob += b"can't happen " + C2 + b"revoked certificatee unknown pc "
    return blob, start + len(b"can't happen ")


def build(arch, detection_only=False):
    data, c2_off = rdata(not detection_only)
    if arch == "amd64":
        text_va, data_va = 0x400100, 0x400200
        c2_va = data_va + c2_off
        pad = b"\x90" * 8
        lea = b"\x48\x8D\x05" + rip_disp(text_va + len(pad), 7, c2_va)
        text = pad + lea + b"\xBB\x13\x00\x00\x00" + b"\x48\x8B\x4C\x24\x58" + b"\xE8\x10\x00\x00\x00"
        if detection_only:
            text = pad * 4
        return build_elf64(text, data)[0]

    if arch == "386":
        text_va, data_va = 0x8048100, 0x8048600
        c2_va = data_va + c2_off
        text = (b"\x90" * 6 + b"\x8D\x05" + struct.pack("<I", c2_va) + b"\x89\x04\x24"
                + b"\xC7\x44\x24\x04\x13\x00\x00\x00" + b"\x8B\x44\x24\x34" + b"\x89\x44\x24\x08"
                + b"\xE8\x20\x00\x00\x00")
        text = b"\x90" * 32 if detection_only else text
        return build_elf32(text, data, machine=3, text_va=0x8048000, data_va=data_va)[0]

    if arch in ("arm5", "arm7"):
        imm, bl_lo = (0x248, 0x3D) if arch == "arm5" else (0x244, 0x59)
        text_va, data_va = 0x10100, 0x10600
        c2_va = data_va + c2_off
        words = [0xE59F0000 | imm, 0xE58D0004, 0xE3A00013, 0xE58D0008, 0xE59D0038, 0xE58D000C,
                 0xEB000000 | bl_lo]
        code = b"".join(struct.pack("<I", w) for w in words)
        code = code.ljust(8 + imm, b"\x00") + struct.pack("<I", c2_va)       # literal pool at pc+8+imm
        code = b"\x00" * 32 if detection_only else code
        return build_elf32(code, data, machine=40, text_va=0x10000, data_va=data_va)[0]

    # MIPS: lui $at,0x51 ; addiu $at,$at,lo  (string lives at 0x51xxxx)
    big = arch == "mips"
    data_va = 0x510100
    lo = (data_va + c2_off - 0x510000) & 0xFFFF
    e = ">I" if big else "<I"
    lw = 0x8FA10040 if big else 0x8FA1003C
    words = [0x3C010051, 0x24210000 | lo, 0xAFA10004, 0x24010013, 0xAFA10008, lw, 0xAFA1000C, 0x0C100000]
    code = b"".join(struct.pack(e, w) for w in words)
    code = b"\x00" * 32 if detection_only else code
    return build_elf32(code, data, machine=8, big_endian=big, text_va=0x400000, data_va=data_va)[0]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    for a in ARCHS:
        (out / f"vulcan_{a}").write_bytes(build(a))
    print("wrote", len(ARCHS), "samples to", out)
