import textwrap

import pytest

from builders import build_elf64, build_pe
from cfgx import Engine
from cfgx.crypto import rc4
from cfgx.resources import parse_spec, select

KEY = b"resource-key-016"
PLAIN = b'{"c2": "198.51.100.23", "port": 8443}'
RC4_PLUGIN = "from cfgx.crypto import rc4\n\ndef decrypt(data, key):\n    return rc4(data, key)\n"


def pe_with_resources(resources, bits=64, rdata=b"MARKER_X\x00"):
    blob, _ = build_pe(b"\x90" * 8, rdata, bits=bits, resources=resources)
    return blob


def run(tmp_path, blob, rule_text, plugin=RC4_PLUGIN, debug=False, name="s.exe"):
    sample, rule, plug = tmp_path / name, tmp_path / "r.yar", tmp_path / "p.py"
    sample.write_bytes(blob)
    rule.write_text(textwrap.dedent(rule_text))
    if plugin is not None:
        plug.write_text(plugin)
    return Engine(rule, plug if plugin is not None else None, debug=debug).run(sample)


RULE = """
    rule R {
      meta:
        config_resource = "RCDATA/101"
        config_adjust   = 4              // skip a 4-byte header
        key_resource    = "RCDATA/KEYRES"
      strings:
        $m = "MARKER_X"
      condition: $m
    }"""


@pytest.mark.parametrize("bits", [64, 32])
def test_data_and_key_from_pe_resources(tmp_path, bits):
    res = [(10, 101, 1033, b"CFG1" + rc4(PLAIN, KEY)), (10, "KEYRES", 1033, KEY), ("BIN", 7, 0, b"other"),
           (24, 1, 1033, b"<manifest/>")]
    out = run(tmp_path, pe_with_resources(res, bits=bits), RULE)
    assert out["status"] == "success", out
    entry = out["config"][0]
    assert entry["config"] == {"c2": "198.51.100.23", "port": 8443}
    assert entry["inputs"]["data"]["via"] == "resource:RCDATA/101/1033"
    assert entry["inputs"]["data"]["section"] == ".rsrc"
    assert entry["inputs"]["data"]["size"] == len(PLAIN)                 # the 4-byte header was skipped
    assert entry["inputs"]["key"]["via"] == "resource:RCDATA/KEYRES/1033"
    assert entry["inputs"]["key"]["value"] == KEY


def test_resource_spec_forms(tmp_path):
    resources = [
        {"type_id": 10, "type": "RCDATA", "name_id": 101, "name": "101", "lang": 1033, "offset": 1, "size": 1},
        {"type_id": 10, "type": "RCDATA", "name_id": None, "name": "CONFIG", "lang": 0, "offset": 2, "size": 1},
        {"type_id": None, "type": "BIN", "name_id": 7, "name": "7", "lang": 0, "offset": 3, "size": 1},
        {"type_id": 24, "type": "MANIFEST", "name_id": 1, "name": "1", "lang": 1033, "offset": 4, "size": 1},
    ]
    offs = lambda spec: [r["offset"] for r in select(resources, spec)]
    assert offs("RCDATA/101") == [1] and offs("RT_RCDATA/101") == [1] and offs("rcdata/101") == [1]
    assert offs("10/101") == [1] and offs("0xA/0x65") == [1]                  # numbers, decimal or hex
    assert offs("RCDATA/CONFIG") == [2] and offs("RCDATA/config") == [2]      # named, case-insensitive
    assert offs("RCDATA/*") == [1, 2] and offs("RCDATA/#0") == [1] and offs("RCDATA/#1") == [2]
    assert offs("BIN/7") == [3] and offs("MANIFEST/1/1033") == [4] and offs("MANIFEST/1/9") == []
    assert offs("ICON/*") == []
    with pytest.raises(ValueError):
        parse_spec("RCDATA")                                                   # needs TYPE/NAME


def test_wildcard_gives_one_candidate_per_resource(tmp_path):
    res = [(10, 1, 0, rc4(b"first entry", KEY)), (10, 2, 0, rc4(b"second entry", KEY)), (10, "KEYRES", 0, KEY)]
    rule = """
        rule R {
          meta:
            config_resource = "RCDATA/1"
            data2_resource  = "RCDATA/2"
            key_resource    = "RCDATA/KEYRES"
          strings: $m = "MARKER_X"
          condition: $m
        }"""
    out = run(tmp_path, pe_with_resources(res), rule)
    by = {e.get("variant"): e["config"] for e in out["config"]}
    assert by[None] == "first entry" and by["2"] == "second entry"           # data2 -> variant 2, key shared


def test_missing_resource_lists_what_exists(tmp_path):
    res = [(10, 101, 0, b"x"), ("BIN", 7, 0, b"y")]
    rule = """
        rule R {
          meta: extract = "config" config_resource = "RCDATA/999"
          strings: $m = "MARKER_X"
          condition: $m
        }"""
    out = run(tmp_path, pe_with_resources(res), rule, plugin=None)
    assert out["status"] == "failed"
    assert any("no resource matches 'RCDATA/999'" in w and "RCDATA/101" in w and "BIN/7" in w for w in out["warnings"])


def test_bad_spec_is_reported(tmp_path):
    rule = 'rule R { meta: config_resource = "RCDATA" strings: $m = "MARKER_X" condition: $m }'
    out = run(tmp_path, pe_with_resources([(10, 1, 0, b"x")]), rule, plugin=None)
    assert any("must look like TYPE/NAME" in w for w in out["warnings"])


def test_named_section_data_and_key(tmp_path):
    rdata = KEY + rc4(PLAIN, KEY) + b"\x00MARKER_X\x00"
    rule = f"""
        rule R {{
          meta:
            key_section    = ".rdata"
            key_size       = 16
            config_section = ".rdata"
            config_adjust  = 16
            config_size    = {len(PLAIN)}
          strings: $m = "MARKER_X"
          condition: $m
        }}"""
    out = run(tmp_path, build_pe(b"\x90" * 8, rdata)[0], rule)
    assert out["status"] == "success", out
    assert out["config"][0]["config"] == {"c2": "198.51.100.23", "port": 8443}
    assert out["config"][0]["inputs"]["data"]["via"] == "section:.rdata"
    assert out["config"][0]["inputs"]["key"]["value"] == KEY


def test_unknown_section_lists_the_sections(tmp_path):
    rule = 'rule R { meta: config_section = ".nope" strings: $m = "MARKER_X" condition: $m }'
    out = run(tmp_path, build_pe(b"\x90" * 8, b"MARKER_X\x00")[0], rule, plugin=None)
    assert any("no section named '.nope'" in w and ".rdata" in w for w in out["warnings"])


def test_resources_need_a_pe(tmp_path):
    blob = build_elf64(b"\x90" * 8, b"MARKER_X\x00")[0]
    rule = 'rule R { meta: config_resource = "RCDATA/1" strings: $m = "MARKER_X" condition: $m }'
    out = run(tmp_path, blob, rule, plugin=None, name="s.elf")
    assert any("needs a PE file (this one is elf)" in w for w in out["warnings"])


def test_rule_only_mode_extracts_resources_and_verbose_lists_them(tmp_path):
    res = [(10, 101, 1033, b"plain config text"), (24, 1, 1033, b"<manifest/>")]
    rule = 'rule R { meta: extract = "config" config_resource = "RCDATA/101" strings: $m = "MARKER_X" condition: $m }'
    sample, r = tmp_path / "s.exe", tmp_path / "r.yar"
    sample.write_bytes(pe_with_resources(res))
    r.write_text(rule)
    out = Engine(r, debug=True).run(sample)                                   # no plugin
    assert out["config"][0]["config"] == {"config": b"plain config text"}
    assert {"type": "MANIFEST", "name": "1", "lang": 1033, "size": 11} in out["sample"]["resources"]
