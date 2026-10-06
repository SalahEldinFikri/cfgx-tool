"""PE32 'FFDroider-like' sample built from the two patterns in examples/ffdroider/rule.yar."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_pe  # noqa: E402

DATA_STRINGS = [b"LoadLibraryA", b"GetProcAddress", b"VirtualAlloc"]   # via $data
DATA2_STRINGS = [b"kernel32.dll", b"user32.dll"]                        # via $data2


def enc(pt: bytes) -> bytes:
    return bytes(b ^ (i % 18 + 5) for i, b in enumerate(pt))


def build():
    rdata, addr = bytearray(), {}
    for marker in (b"FFDroider", b"Software\\ffdroider"):
        rdata += marker + b"\x00"
    for name, pt in [(f"a{i}", s) for i, s in enumerate(DATA_STRINGS)] + \
                    [(f"b{i}", s) for i, s in enumerate(DATA2_STRINGS)]:
        addr[name] = len(rdata)
        rdata += enc(pt) + b"\x00"
    rdata += b"\x00" * 8
    va = lambda n: (0x402000 + addr[n]).to_bytes(4, "little")
    iat = (0x402000 + len(rdata) - 4).to_bytes(4, "little")

    text = b"\x90" * 8
    for i in range(len(DATA_STRINGS)):                                  # $data blocks
        text += (b"\x6A\x00" + b"\x68" + va(f"a{i}") + b"\xE8\x10\x00\x00\x00"
                 + b"\x52" + b"\xFF\x15" + iat + b"\x89\x45\xE8" + b"\x90" * 30)
    for i in range(len(DATA2_STRINGS)):                                 # $data2 blocks
        text += (b"\x6A\x00" + b"\x68" + va(f"b{i}") + b"\xE8\x20\x00\x00\x00"
                 + b"\x8B\x4D\xF8\x51" + b"\xFF\x55\xE8" + b"\x89\x45\xF4" + b"\x90" * 30)
    return build_pe(text, bytes(rdata), bits=32)[0]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "ffdroider_demo.exe").write_bytes(build())
    print("wrote", out / "ffdroider_demo.exe")
