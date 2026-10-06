import json
import textwrap

import pytest

from builders import build_elf64, build_pe, rip_disp
from cfgx import Engine
from cfgx.cli import main
from cfgx.crypto import rc4
from cfgx.errors import CfgxError
from cfgx.formats import load_image
from cfgx.refs import find_references

KEY = b"KEY1234567890123"
CONFIG = {"c2": "10.0.0.5", "port": 443}
PLAIN = json.dumps(CONFIG, separators=(",", ":")).encode().ljust(48, b" ")
CIPHER = rc4(PLAIN, KEY)

RC4_PLUGIN = """
from cfgx.crypto import rc4

def decrypt(data, key):
    return rc4(data, key)
"""


def write(path, text):
    path.write_text(textwrap.dedent(text))
    return path


def pe64_sample(tmp_path, lea_opcode=b"\x48\x8D\x05"):
    """.text: <lea reg,[rip+config]> nop ; .rdata: config + key literal."""
    rdata = CIPHER + b"\x00" * 16 + KEY + b"\x00"
    text_va = 0x140001000
    cfg_va = 0x140002000
    disp = rip_disp(text_va + 16, 7, cfg_va)
    text = b"\x90" * 16 + lea_opcode + disp + b"\x90" * 8
    blob, _ = build_pe(text, rdata)
    p = tmp_path / "sample64.exe"
    p.write_bytes(blob)
    return p


# ------------------------------------------------------------------ the happy path
@pytest.mark.parametrize("lea", [b"\x48\x8D\x05", b"\x48\x8D\x0D", b"\x4C\x8D\x05", b"\x48\x8D\x35"],
                         ids=["rax", "rcx", "r8", "rsi"])
def test_pe64_follows_any_rip_relative_lea(tmp_path, lea):
    # Regression: the old resolver only knew rcx/rdx/r15.
    sample = pe64_sample(tmp_path, lea)
    mask = lea.hex(" ")
    rule = write(tmp_path / "r.yar", f"""
        rule T {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
          strings:
            $config = {{ {mask} ?? ?? ?? ?? 90 }}
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    plugin = write(tmp_path / "p.py", RC4_PLUGIN)

    res = Engine(rule, plugin).run(sample)

    assert res["status"] == "success", res
    entry = res["config"][0]
    assert entry["config"] == CONFIG
    assert entry["inputs"]["data"]["via"] == "ref:lea"
    assert entry["inputs"]["data"]["section"] == ".rdata"
    assert entry["inputs"]["key"]["value"] == KEY
    assert res["sample"]["format"] == "pe" and res["sample"]["arch"] == "x64"


def test_pe32_push_and_mov(tmp_path):
    rdata = CIPHER + b"\x00" * 16 + KEY + b"\x00"
    cfg_va, key_va = 0x402000, 0x402000 + len(CIPHER) + 16
    text = (b"\x90" * 8 + b"\x68" + cfg_va.to_bytes(4, "little")      # push config
            + b"\xB9" + key_va.to_bytes(4, "little") + b"\x90" * 4)   # mov ecx, key
    blob, _ = build_pe(text, rdata, bits=32)
    sample = tmp_path / "s32.exe"
    sample.write_bytes(blob)
    rule = write(tmp_path / "r.yar", f"""
        rule T32 {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
          strings:
            $config = {{ 68 ?? ?? ?? ?? }}
            $key = {{ B9 ?? ?? ?? ?? }}
          condition: all of them
        }}""")
    res = Engine(rule, write(tmp_path / "p.py", RC4_PLUGIN)).run(sample)
    assert res["status"] == "success", res
    assert res["config"][0]["config"] == CONFIG
    assert res["sample"]["arch"] == "x86"


def test_elf64_rip_relative(tmp_path):
    # Regression: ELF used to get no reference resolution at all.
    data = CIPHER + KEY + b"\x00"
    text_va, data_va = 0x400100, 0x400200
    text = b"\x90" * 4 + b"\x48\x8D\x05" + rip_disp(text_va + 4, 7, data_va) + b"\x90" * 4
    blob, _ = build_elf64(text, data)
    sample = tmp_path / "s.elf"
    sample.write_bytes(blob)
    rule = write(tmp_path / "r.yar", f"""
        rule E {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
            key_adjust = 0
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    res = Engine(rule, write(tmp_path / "p.py", RC4_PLUGIN)).run(sample)
    assert res["status"] == "success", res
    assert res["config"][0]["config"] == CONFIG
    assert res["sample"]["format"] == "elf"


def test_raw_blob_with_adjust(tmp_path):
    blob = b"junk" * 10 + b"CFG:" + CIPHER + b"pad" + KEY + b"tail"
    sample = tmp_path / "dump.bin"
    sample.write_bytes(blob)
    rule = write(tmp_path / "r.yar", f"""
        rule Raw {{
          meta:
            config_adjust = 4
            config_size = {len(CIPHER)}
          strings:
            $config = "CFG:"
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    res = Engine(rule, write(tmp_path / "p.py", RC4_PLUGIN)).run(sample)
    assert res["status"] == "success", res
    assert res["sample"]["format"] == "raw"
    assert res["config"][0]["config"] == CONFIG


# ------------------------------------------------------------------ resolver / mapping fixes
def test_bss_reference_is_not_followed(tmp_path):
    # Regression: rva_to_offset used max(VirtualSize, RawSize) and returned
    # offsets for memory that has no bytes in the file.
    text = b"\x48\x8D\x05" + rip_disp(0x140001000, 7, 0x140003010) + b"\x90"
    blob, layout = build_pe(text, b"A" * 16)
    sample = tmp_path / "b.exe"
    sample.write_bytes(blob)
    image = load_image(sample)
    assert image.va_to_offset(layout["bss_va"] + 0x10) is None
    assert image.rva_to_offset(0x3010) is None
    off = layout["text_off"]
    refs = find_references(image, off, blob[off:off + 8])
    # kept as a placeholder (so ref_index stays stable) but with no file offset to read
    assert [r["offset"] for r in refs] == [None]
    assert refs[0]["va"] == layout["bss_va"] + 0x10
    image.close()


def test_non_pointer_bytes_do_not_create_references(tmp_path):
    blob, _ = build_pe(b"\x68\x00\x00\x00\x00\x90\x90\x90", b"A" * 16, bits=32)
    p = tmp_path / "x.exe"
    p.write_bytes(blob)
    image = load_image(p)
    assert find_references(image, 0x200, b"\x68\x00\x00\x00\x00") == []   # push 0 -> not in image
    image.close()


# ------------------------------------------------------------------ plugin features
def test_several_keys_picks_the_one_that_decrypts(tmp_path):
    rdata = CIPHER + b"\x00" * 16 + b"WRONGKEY00000000" + b"\x00" + KEY + b"\x00"
    text = b"\x90" * 16 + b"\x48\x8D\x05" + rip_disp(0x140001010, 7, 0x140002000) + b"\x90" * 8
    blob, _ = build_pe(text, rdata)
    sample = tmp_path / "s.exe"
    sample.write_bytes(blob)
    rule = write(tmp_path / "r.yar", f"""
        rule M {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
            $key = /[A-Z0-9]{{16}}\\x00/
          condition: all of them
        }}""")
    res = Engine(rule, write(tmp_path / "p.py", RC4_PLUGIN)).run(sample)
    assert res["status"] == "success", res
    assert len(res["config"]) == 1
    assert res["config"][0]["config"] == CONFIG


def test_validate_and_parse_hooks(tmp_path):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", f"""
        rule H {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    plugin = write(tmp_path / "p.py", RC4_PLUGIN + """
FAMILY = "TestFamily"

def validate(plaintext):
    return plaintext.startswith(b"{")

def parse(plaintext, ctx):
    import json
    cfg = json.loads(plaintext)
    cfg["rule_seen"] = ctx.rule
    return cfg
""")
    res = Engine(rule, plugin).run(sample)
    assert res["status"] == "success"
    assert res["config"][0]["family"] == "TestFamily"
    assert res["config"][0]["config"]["rule_seen"] == "H"


def test_missing_parameter_gives_clear_error(tmp_path):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", f"""
        rule P {{
          meta:
            config_size = {len(CIPHER)}
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
          condition: all of them
        }}""")
    plugin = write(tmp_path / "p.py", "def decrypt(data, key):\n    return data\n")
    res = Engine(rule, plugin).run(sample)
    assert res["status"] == "failed"
    assert "needs 'key'" in res["errors"][0] and "$config" in res["errors"][0]


def test_legacy_extract_plugin_still_works(tmp_path):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", """
        rule L {
          strings:
            $config = { 48 8D 05 ?? ?? ?? ?? 90 }
          condition: all of them
        }""")
    plugin = write(tmp_path / "p.py", """
        def extract(matches, reader):
            m = matches[0]
            data = m["references"][0]["data"][:8]
            return {"status": "success", "config": {"first8": data.hex(), "section": m["section"]}}
        """)
    res = Engine(rule, plugin).run(sample)
    assert res["status"] == "success", res
    assert res["config"][0]["config"]["section"] == ".text"


def test_locate_only_mode_without_plugin(tmp_path):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", f"""
        rule Loc {{
          meta:
            config_size = {len(CIPHER)}
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    res = Engine(rule).run(sample)
    assert res["status"] == "located"
    loc = res["config"][0]["located"]
    assert loc["config"][0]["section"] == ".rdata" and "value" not in loc["config"][0]
    assert res["config"][0]["config"]["key"] == KEY


def test_warns_when_config_has_no_size(tmp_path):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", """
        rule W {
          strings:
            $config = { 48 8D 05 ?? ?? ?? ?? 90 }
          condition: all of them
        }""")
    res = Engine(rule).run(sample)
    assert any("config_size" in w for w in res["warnings"])


# ------------------------------------------------------------------ misc / CLI
def test_triple_des_module_is_importable():
    # Regression: the module used to be called 3des.py and could not be imported.
    from cfgx.algorithms.triple_des import decrypt   # noqa: F401


def test_bad_rule_raises_clean_error(tmp_path):
    bad = write(tmp_path / "bad.yar", "rule X { strings: $a = condition: }")
    with pytest.raises(CfgxError):
        Engine(bad)


def test_cli_exit_codes_and_output(tmp_path, capsys):
    sample = pe64_sample(tmp_path)
    other = tmp_path / "samples" / "notmatching.bin"
    other.parent.mkdir()
    other.write_bytes(b"nothing here")
    (tmp_path / "samples" / "sample64.exe").write_bytes(sample.read_bytes())
    rule = write(tmp_path / "r.yar", f"""
        rule C {{
          meta:
            config_size = {len(CIPHER)}
            key_size = 16
          strings:
            $config = {{ 48 8D 05 ?? ?? ?? ?? 90 }}
            $key = "KEY1234567890123"
          condition: all of them
        }}""")
    plugin = write(tmp_path / "p.py", RC4_PLUGIN)
    out = tmp_path / "out"

    assert main([str(rule), str(tmp_path / "samples"), str(plugin), "-o", str(out), "-q"]) == 0
    assert (out / "C" / "sample64.exe.cfgx.json").exists()              # filed under its family
    assert (out / "C" / "C.family.json").exists()
    assert (out / "_unmatched" / "notmatching.bin.cfgx.json").exists()
    summary = json.loads((out / "summary.json").read_text())
    assert {s["status"] for s in summary} == {"success", "no_match"}

    assert main([str(rule), str(other), str(plugin), "-q"]) == 1          # nothing extracted
    assert main([str(tmp_path / "missing.yar"), str(sample), "-q"]) == 2   # fatal


# ------------------------------------------------------------------ diagnostics
def test_os_hint_for_windows_errno22():
    from cfgx.errors import os_hint
    err = OSError(22, "Invalid argument", "C:\\samples\\x")
    assert "antivirus" in os_hint(err, nt=True)
    assert os_hint(err, nt=False) is None
    assert os_hint(ValueError("x"), nt=True) is None


def test_unreadable_sample_reports_error_and_traceback(tmp_path, monkeypatch):
    sample = pe64_sample(tmp_path)
    rule = write(tmp_path / "r.yar", 'rule X { strings: $a = "KEY" condition: $a }')
    import cfgx.engine as eng

    def boom(*a, **k):
        raise OSError(22, "Invalid argument", str(sample))

    monkeypatch.setattr(eng, "load_image", boom)
    res = Engine(rule, debug=True).run(sample)
    assert res["status"] == "error"
    assert "Invalid argument" in res["errors"][0]
    assert "Traceback" in res["traceback"]


def test_reader_falls_back_when_mmap_fails(tmp_path, monkeypatch):
    import mmap
    from cfgx.reader import Reader
    f = tmp_path / "f.bin"
    f.write_bytes(b"hello KEY world\x00tail")

    def nope(*a, **k):
        raise OSError(22, "Invalid argument")

    monkeypatch.setattr(mmap, "mmap", nope)
    with Reader(f) as r:
        assert r.find(b"KEY") == 6
        assert r.read_cstring(6) == b"KEY world"
        assert r[0:5] == b"hello"
