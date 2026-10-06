from pathlib import Path

import pytest

import easystealer_demo as demo
from cfgx import Engine

RULE = Path(__file__).resolve().parent.parent / "examples" / "easystealer" / "rule.yar"


def test_easystealer_c2_without_any_plugin(tmp_path):
    sample = tmp_path / "e.exe"
    sample.write_bytes(demo.build())
    res = Engine(RULE).run(sample)

    assert res["status"] == "located", res
    entry = res["config"][0]
    assert entry["config"] == {"c2": b"46.151.29.182"}          # exactly 13 bytes, no Go-blob junk
    assert list(entry["located"]) == ["c2"]                       # $m* strings are not extracted
    assert entry["located"]["c2"][0]["via"] == "ref:lea"
    assert entry["located"]["c2"][0]["size"] == 13


@pytest.mark.parametrize("c2", [b"1.2.3.4", b"255.255.255.255", b"10.20.30.40"])
def test_length_comes_from_the_code(tmp_path, c2):
    sample = tmp_path / "e.exe"
    sample.write_bytes(demo.build(c2))
    res = Engine(RULE).run(sample)
    assert res["config"][0]["config"]["c2"] == c2


def test_size_at_outside_the_match_warns(tmp_path):
    rule = tmp_path / "r.yar"
    rule.write_text(RULE.read_text().replace("c2_size_at = 25", "c2_size_at = 99"))
    sample = tmp_path / "e.exe"
    sample.write_bytes(demo.build())
    res = Engine(rule).run(sample)
    assert res["status"] == "failed"
    assert any("size_at=99" in w for w in res["warnings"])


def test_extract_meta_must_match_a_string(tmp_path):
    rule = tmp_path / "r.yar"
    rule.write_text(RULE.read_text().replace('extract    = "c2"', 'extract    = "nope"'))
    sample = tmp_path / "e.exe"
    sample.write_bytes(demo.build())
    res = Engine(rule).run(sample)
    assert res["status"] == "failed" and "matches none" in res["errors"][0]
