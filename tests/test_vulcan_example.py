from pathlib import Path

import pytest

import vulcan_demo as demo
from builders import build_elf32
from cfgx import Engine
from cfgx.cli import main
from cfgx.formats import load_image
from cfgx.reader import Reader
from cfgx.refs import find_references

RULE = Path(__file__).resolve().parent.parent / "examples" / "vulcan" / "rule.yar"


@pytest.mark.parametrize("arch", demo.ARCHS)
def test_c2_extracted_on_every_architecture(tmp_path, arch):
    sample = tmp_path / f"vulcan_{arch}"
    sample.write_bytes(demo.build(arch))
    res = Engine(RULE).run(sample)

    assert res["status"] == "located", res
    assert res["detections"] == ["Family_Vulcan"]
    assert len(res["config"]) == 1
    entry = res["config"][0]
    assert entry["rule"] == demo.EXPECTED_RULE[arch]
    assert entry["family"] == "Vulcan"
    assert entry["config"] == {"Config": demo.C2}                 # 19 bytes, no Go-blob junk
    assert entry["located"]["Config"][0]["size"] == 19


def test_big_and_little_endian_mips_are_detected_as_such(tmp_path):
    for arch, endian in (("mips", "big"), ("mipsle", "little")):
        p = tmp_path / arch
        p.write_bytes(demo.build(arch))
        res = Engine(RULE).run(p)
        assert res["sample"]["arch"] == "mips" and res["sample"]["endian"] == endian


def test_detection_only_sample(tmp_path, capsys):
    p = tmp_path / "vulcan_amd64"
    p.write_bytes(demo.build("amd64", detection_only=True))
    res = Engine(RULE).run(p)
    assert res["status"] == "detected" and res["config"] == []
    code = main([str(RULE), str(p), "--color", "never"])
    out = capsys.readouterr().out
    assert code == 1
    assert "family detected, no configuration extracted" in out and "1 detected only" in out


def test_family_vulcan_markers_are_not_dumped(tmp_path):
    p = tmp_path / "v"
    p.write_bytes(demo.build("386"))
    res = Engine(RULE).run(p)
    assert all(e["rule"] != "Family_Vulcan" for e in res["config"])


def test_mips_lui_addiu_sign_extension(tmp_path):
    # lui $at,0x52 ; addiu $at,$at,0xFF00  ->  0x520000 - 0x100 = 0x51FF00
    import struct
    text = struct.pack(">II", 0x3C010052, 0x2421FF00)
    blob, info = build_elf32(text, b"hello" + b"\x00" * 16, machine=8, big_endian=True,
                             text_va=0x400000, data_va=0x51FF00)
    f = tmp_path / "m"
    f.write_bytes(blob)
    image = load_image(f)
    with Reader(f, image) as r:
        refs = find_references(image, 0x100, text, r.read)
    image.close()
    assert [x["va"] for x in refs] == [0x51FF00] and refs[0]["kind"] == "lui+addiu"
