"""Builds a PE32 and a PE64 'Stealc-like' sample from the exact byte patterns in
examples/stealc/rule.yar.  Run `python tests/stealc_demo.py OUTDIR` to get them."""
import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_pe, rip_disp          # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from cfgx.crypto import rc4                       # noqa: E402

GUID = b"%08lX-%04hX-%04hX-%02hhX%02hhX-%02hhX%02hhX%02hhX%02hhX%02hhX%02hhX"
KEY32 = b"A1b2C3d4E5f6G7h8I9"          # 18 bytes = the 6A 12 in the rule
KEY64 = b"Zq8Xw3Lp0Vn5Ty7Rk2"
STRINGS = [b"http://203.0.113.7", b"/4f9a1c2e7b3d5a60.php", b"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"]


def _rdata(key, items):
    blob, addr = bytearray(), {}

    def add(name, data):
        addr[name] = len(blob)
        blob.extend(data + b"\x00")
        while len(blob) % 4:
            blob.append(0)

    add("guid", GUID)
    add("key", key)
    add("state", b"\x00" * 16 + b"x")
    for i, s in enumerate(items):
        add(f"b64_{i}", base64.b64encode(rc4(s, key)))
    return bytes(blob), addr


def build_pe32():
    rdata, a = _rdata(KEY32, STRINGS)

    def code(rdata_va):
        va = lambda n: (rdata_va + a[n]).to_bytes(4, "little")
        c = b"\x90" * 6 + b"\x6A\x12\x68" + va("key") + b"\xB9" + va("state") + b"\xE8\x10\x00\x00\x00" + b"\x90" * 6
        for i in range(len(STRINGS)):
            c += (b"\x68" + va(f"b64_{i}") + b"\x8D\x4D\xF0" + b"\xE8\x20\x00\x00\x00"
                  + b"\x8D\x55\xE0" + b"\x8D\x4D\xD0" + b"\xE8\x30\x00\x00\x00" + b"\x90" * 6)
        return c

    rdata_rva = max(0x2000, 0x1000 + (len(code(0)) + 0xFFF) // 0x1000 * 0x1000)
    return build_pe(code(0x400000 + rdata_rva), rdata, bits=32)[0]


def build_pe64():
    rdata, a = _rdata(KEY64, STRINGS)
    text_va, rdata_va = 0x140001000, 0x140002000
    code = bytearray(b"\x90" * 6)

    def lea(opcode3, name):
        code.extend(opcode3 + rip_disp(text_va + len(code), 7, rdata_va + a[name]))

    lea(b"\x4C\x8D\x3D", "key")                        # lea r15, key_string
    code += b"\x49\x8B\xCF" + b"\xE8\x10\x00\x00\x00" + b"\x33\xC0" + b"\x90" * 6
    for i in range(len(STRINGS)):
        lea(b"\x48\x8D\x0D", f"b64_{i}")               # lea rcx, ciphertext
        code += b"\x4C\x8D\x45\x20" + b"\xE8\x20\x00\x00\x00" + b"\x90\x90"
        lea(b"\x48\x8D\x15", f"b64_{i}")               # lea rdx, ciphertext
        code += b"\x48\x8D\x4D\x40" + b"\xE8\x30\x00\x00\x00" + b"\x90" * 6
    return build_pe(bytes(code), rdata, bits=64)[0]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "stealc_demo_x86.exe").write_bytes(build_pe32())
    (out / "stealc_demo_x64.exe").write_bytes(build_pe64())
    print("wrote", out / "stealc_demo_x86.exe", "and", out / "stealc_demo_x64.exe")
