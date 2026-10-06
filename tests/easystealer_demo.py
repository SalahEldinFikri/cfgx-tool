"""PE32 'EasyStealer-like' sample built from the byte pattern in examples/easystealer/rule.yar."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_pe  # noqa: E402

C2 = b"46.151.29.182"
MARKERS = [b"easy/decrypt.Start", b"easy/decrypt.Start.func1", b"easy/decrypt.GetMePath",
           b"easy/decrypt.RandomString", b"easy/decrypt.FoundBrowser", b"easy/decrypt.GrabFromBrowser",
           b"easy/decrypt.GrabFromBrowser.func1", b"easy/decrypt.MasterKey", b"easy/user.EX",
           b"easy/user.Return", b"easy/user.init.0", b"easy/user.GetHWID", b"easy/user.SystemInfo",
           b"easy/user.init", b"easy/zip.addFiles"]


def build(c2=C2):
    # Go keeps strings in one blob with no NULs between them
    blob = b"can't happen case 6 " + c2 + b": unknown pc Accept-Ranges bad record MAC " + b"\x00" * 4
    rdata = b"\x00".join(MARKERS) + b"\x00\x00\x00\x00" + blob
    c2_va = 0x402000 + rdata.index(c2)
    text = (b"\x90" * 8
            + b"\xC7\x04\x24\x13\x00\x00\x00"                       # mov [esp], 13h
            + b"\xE8\x10\x00\x00\x00"                               # call log_SetFlags
            + b"\x8D\x05" + c2_va.to_bytes(4, "little")             # lea eax, blob+x
            + b"\x89\x04\x24"                                       # mov [esp], eax
            + b"\xC7\x44\x24\x04" + len(c2).to_bytes(4, "little")   # mov [esp+4], len
            + b"\xE8\x20\x00\x00\x00"                               # call InitServer
            + b"\x90" * 8)
    return build_pe(text, rdata, bits=32)[0]


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "easystealer_demo.exe").write_bytes(build())
    print("wrote", out / "easystealer_demo.exe")
