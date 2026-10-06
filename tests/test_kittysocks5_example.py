from pathlib import Path

import kittysocks5_demo as demo
from cfgx import Engine
from cfgx.consts import _recover_arm
from cfgx.formats import load_image
from cfgx.refs import find_references

EX = Path(__file__).resolve().parent.parent / "examples" / "kittysocks5"


def test_kittysocks5_full_flow(tmp_path):
    sample = tmp_path / "k.elf"
    sample.write_bytes(demo.build())
    res = Engine(EX / "rule.yar", EX / "plugin.py").run(sample)

    assert res["status"] == "success", res
    assert res["sample"]["format"] == "elf" and res["sample"]["arch"] == "arm"
    from cfgx.output import auto_parse
    # text entries are auto-parsed to str, binary entries stay bytes
    assert [e["config"] for e in res["config"]] == [auto_parse(p) for p in demo.PLAINTEXTS]
    assert [e["inputs"]["data"]["size"] for e in res["config"]] == demo.SIZES
    assert all(e["inputs"]["data"]["via"] == "ref:ldr" for e in res["config"])
    assert res["config"][0]["inputs"]["key"]["value"] == demo.KEY


def test_binary_entries_are_not_dropped_without_validate(tmp_path):
    # Regression: with no validate(), several data blobs used to be treated as alternatives and
    # only the printable ones were kept.
    sample = tmp_path / "k.elf"
    sample.write_bytes(demo.build())
    res = Engine(EX / "rule.yar", EX / "plugin.py").run(sample)
    assert len(res["config"]) == 7


def test_arm_literal_pool_reference(tmp_path):
    sample = tmp_path / "k.elf"
    sample.write_bytes(demo.build())
    image = load_image(sample)
    code = sample.read_bytes()
    from cfgx.reader import Reader
    with Reader(sample, image) as r:
        off = demo.TEXT_OFF
        refs = find_references(image, off, code[off:off + 8], r.read)
        assert len(refs) == 1 and refs[0]["kind"] == "ldr"
        assert refs[0]["va"] == demo.BASE + demo.DATA_OFF          # points at table_key
        assert find_references(image, off, code[off:off + 8]) == []  # no reader -> no pool access
    image.close()


def test_size_recovery_is_not_fooled_by_register_offset_loads():
    # LDR R2,[R1,R3] has bit 25 set but is not a data-processing instruction; the old decoder
    # treated it as MOV/ADD-immediate on R2.
    bl = bytes([0, 0, 0, 0xEB])
    code = bytes([0x03, 0x20, 0x91, 0xE7]) + bl
    assert _recover_arm(lambda o, n: code[o:o + n], 0, "r2", 64) is None
    code = bytes([0x52, 0x2F, 0xA0, 0xE3, 0x02, 0x20, 0x82, 0xE2]) + bl
    assert _recover_arm(lambda o, n: code[o:o + n], 0, "r2", 64) == 0x14A


def test_size_reg_on_unsupported_arch_warns(tmp_path):
    from builders import build_pe
    rule = tmp_path / "r.yar"
    rule.write_text('rule X { meta: config_size_reg = "r2" strings: $config = { 68 ?? ?? ?? ?? } condition: $config }')
    blob, _ = build_pe(b"\x68\x00\x20\x40\x00\x90" * 2, b"A" * 32, bits=32)
    s = tmp_path / "s.exe"
    s.write_bytes(blob)
    res = Engine(rule).run(s)
    assert any("size_reg is not supported" in w for w in res["warnings"])
