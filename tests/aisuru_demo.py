"""Synthetic AISURU samples (x86 v1, x86 v2, ARM) built from the byte patterns in examples/aisuru/rule.yar.

``literal_three`` is a LINE-BY-LINE transcription of the decompiled routine three (HIBYTE, __ROR4__,
__ROL1__ and the 64-bit v8 included), used as an independent oracle for the plugin's simplified cipher."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_elf32  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cfgx.crypto import rc4  # noqa: E402


# ------------------------------------------------------------------ oracle: sub_804D070 + routine three, literally
M = 0xFFFFFFFF


def literal_sub_804D070(key):
    """The decompiled function on a 272-byte ctx (a1): S-box in bytes 0..255, key words in a1[64..67]."""
    a1, a3 = bytearray(272), len(key)
    v = bytearray(16)                                        # v17..v20, contiguous on the stack
    for idx in range(16):                                    # the cascade of `if (a3 <= idx)` branches
        v[idx] = key[idx] if idx < a3 else v[idx % a3]
    dword = lambda b, off: int.from_bytes(b[off:off + 4], "little")
    bswap = lambda x: int.from_bytes(x.to_bytes(4, "little"), "big")
    for n in range(4):
        a1[256 + 4 * n:260 + 4 * n] = bswap(dword(v, 4 * n)).to_bytes(4, "little")      # a1[64+n] = _byteswap_ulong
    v6, v5 = 13, 1
    while True:                                              # *((_BYTE *)a1 + v5++ - 1) = v6; v6 -= 89;
        a1[v5 - 1] = v6 & 0xFF
        v5 += 1
        v6 -= 89
        if v5 == 257:
            break
    v7 = 0
    for i in range(256):
        v9 = a1[i]
        v7 = ((dword(a1, 256 + 4 * (i % 4)) >> (i % 32)) + v9 + v7) & 0xFF
        a1[i] = a1[v7]
        a1[v7] = v9
    v10 = -526070826
    for j in range(5):
        for k in range(256):
            v10 = ((1103515245 * v10 + 12345) & M)
            v12 = (v7 + (((v10 * a1[k]) & M) >> 24)) & 0xFF                              # char
            v13 = (v10 ^ dword(a1, 256 + 4 * ((k + j) % 4)) ^ a1[k]) & M
            a1[k] = v13 & 0xFF
            v14 = ((v13 + v12) & 0xFF)
            v7 = (v7 & ~0xFF) | v14                                                      # LOBYTE(v7) = v14
            a1[k] = a1[v14]
            a1[v14] = v13 & 0xFF
    return bytes(a1[:256])


def literal_three(buf, key):
    ror4 = lambda x, n: ((x & M) >> n | (x << (32 - n))) & M
    rol1 = lambda x, n: (((x & 0xFF) << n) | ((x & 0xFF) >> (8 - n))) & 0xFF
    hibyte64 = lambda x: (x >> 56) & 0xFF
    hibyte_hidword = lambda x: ((x >> 32) >> 24) & 0xFF
    v16 = list(literal_sub_804D070(key))                      # sub_8059000(v16, v15, 256) is a plain memcpy
    out, v14 = bytearray(buf), len(buf)
    if not v14:
        return bytes(out)
    v4 = v5 = v13 = 0
    v12, v6 = 1, 1
    while True:
        v4 = (v4 + 1) % 256
        v7 = v16[v4]
        v5 = (v5 + v7) % 256
        v8 = v13 + v16[(v4 + v5) % 256]                                   # __int64
        v13 = ((hibyte64(v8) + v13 + v16[(v4 + v5) % 256]) & 0xFF) - hibyte_hidword(v8)
        v16[v4] = v16[v5]
        v16[v5] = v7
        v12 = ror4(v12, 31)
        if v12 & 1:
            v12 ^= 0xD800A4
        v9 = v16[(v16[(v4 + v5) % 256] + v16[(v5 + v13) % 256]) & 0xFF]
        out[v6 - 1] ^= (((v12 ^ v9) & 0xFF) >> 4 ^ rol1(v12 ^ v9, 3)) & 0xFF
        v6 += 1
        if v6 == v14 + 1:
            break
    return bytes(out)


# ------------------------------------------------------------------ x86 v1: RC4_Key_sch + add_entry(len, data, eax)
KEY1 = b"Qe7Lm2Zk9Vb4Tx1W"
V1_ENTRIES = [b"cnc.example.org:5555", b"/bin/busybox ECCI", b"GET /ping HTTP/1.1", b"Mozilla/5.0"]
TEXT_VA, DATA_VA = 0x8048000, 0x8048600


def build_x86_v1():
    data, addr = bytearray(KEY1), {}
    for i, pt in enumerate(V1_ENTRIES):
        addr[i] = len(data)
        data += rc4(pt, KEY1)
    ctx_va = DATA_VA + len(data) + 0x10                                   # RC4 state buffer: .bss (not in the file)
    le = lambda v: struct.pack("<I", v)
    code = b"\x51\x6A\x10\x68" + le(DATA_VA) + b"\x68" + le(ctx_va) + b"\xE8\x10\x00\x00\x00" + b"\x90" * 4
    for i, pt in enumerate(V1_ENTRIES):
        code += b"\x6A" + bytes([len(pt)]) + (b"\x89\xC3" if i % 2 else b"")     # odd ones: a gap before the push
        code += b"\x68" + le(DATA_VA + addr[i]) + b"\x50" + b"\xE8\x20\x00\x00\x00" + b"\x90" * 4
    return build_elf32(code, bytes(data), machine=3, text_va=TEXT_VA, data_va=DATA_VA)[0]


# ------------------------------------------------------------------ x86 v2: blobs copied with rep movsd (+ tail), custom cipher
KEY2 = b"PJbiNbbeasddDfsc"
V2_CONFIG = [b"http://update.example.net/a", b"/bin/busybox ECCI; ls", b"ssh-scan:22,23,2323", b"abcdefghijklmnopqrstuvwxyz012345"]
V2_BLOBS = [b"/bin/busybox echo AIRASHI > /proc/sys/kernel/hostname" + b"." * 80,     # > 127 bytes: push imm32
            b"GET /ping HTTP/1.1\r\nHost: x\r\n", b"\x51\x13", b"\r\n"]            # last one is stored unencrypted


def build_x86_v2(ptr_to_key=True):
    data, addr = bytearray(KEY2), []
    data += struct.pack("<I", DATA_VA if ptr_to_key else 0)               # off_805BD48: a POINTER to the key string
    for pt in V2_CONFIG + V2_BLOBS:
        addr.append(len(data))
        data += pt if pt == b"\r\n" else literal_three(pt, KEY2)
    var_va = DATA_VA + len(data) + 0x20                                   # dword_805D774: .bss
    le = lambda v: struct.pack("<I", v)
    code = (b"\xB9\x10\x00\x00\x00" + b"\x8B\x15" + le(DATA_VA + 16) + b"\x89\xF0"             # $key
            + b"\xE8" + struct.pack("<I", (-0x1234) & 0xFFFFFFFF) + b"\x90" * 4)
    for i, pt in enumerate(V2_CONFIG):                                    # $config: N dwords + movsw/movsb tail
        dwords, tail = divmod(len(pt), 4)
        code += (b"\xBE" + le(DATA_VA + addr[i]) + b"\xB9" + bytes([dwords]) + b"\x00\x00\x00" + b"\xF3\xA5"
                 + (b"\x66\xA5" if tail & 2 else b"") + (b"\xA4" if tail & 1 else b"")
                 + b"\xA1" + le(var_va) + b"\x90" * 4)
    for j, pt in enumerate(V2_BLOBS):                                     # $config2: push len ; push blob ; push esi
        push_len = b"\x6A" + bytes([len(pt)]) if len(pt) < 128 else b"\x68" + le(len(pt))
        code += b"\x50" + push_len + b"\x68" + le(DATA_VA + addr[len(V2_CONFIG) + j]) + b"\x56" \
                + b"\xE8\x30\x00\x00\x00" + b"\x90" * 4
    return build_elf32(code, bytes(data), machine=3, text_va=TEXT_VA, data_va=DATA_VA)[0]


# ------------------------------------------------------------------ ARM: LDR R0,=ctx ; LDR R1,=data ; MOV R2,#0x10 ; BL
ARM_KEY = b"z9Xc3Vb7Nm1Lk5Jh"
ARM_ENTRIES = [b"198.51.100.7:443", b"POST /gate.php\r\n", b"Mozilla/5.0 (X11"]       # 16 bytes each (MOV R2,#0x10)


def build_arm(sections=False):
    data = bytearray(ARM_KEY)
    for pt in ARM_ENTRIES:
        data += rc4(pt, ARM_KEY)
    dva = 0x10600
    ctx_va = dva + len(data) + 0x10                                       # state buffer in .bss
    code = bytearray(0x40 * (1 + len(ARM_ENTRIES)))

    def site(k, imm, first, second):
        base = 0x40 * k
        code[base:base + 16] = struct.pack("<4I", 0xE59F0000 | imm, 0xE59F1000 | imm, 0xE3A02010, 0xEB000010)
        code[base + 8 + imm:base + 12 + imm] = struct.pack("<I", first)          # pool word of LDR R0
        code[base + 12 + imm:base + 16 + imm] = struct.pack("<I", second)        # pool word of LDR R1

    site(0, 0x2C, ctx_va, dva)                                            # $key    (imm 0x2C in the rule)
    for i in range(len(ARM_ENTRIES)):
        site(1 + i, 0x30, ctx_va, dva + 16 + 16 * i)                      # $config (imm 0x30 in the rule)
    return build_elf32(bytes(code), bytes(data), machine=40, text_va=0x10000, data_va=dva, sections=sections)[0]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "aisuru_x86_v1").write_bytes(build_x86_v1())
    (out / "aisuru_x86_v2").write_bytes(build_x86_v2())
    (out / "aisuru_arm").write_bytes(build_arm())
    print("wrote 3 samples to", out)
