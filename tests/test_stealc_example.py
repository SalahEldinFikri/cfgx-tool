from pathlib import Path

import pytest

import stealc_demo as demo
from cfgx import Engine

EX = Path(__file__).resolve().parent.parent / "examples" / "stealc"


@pytest.mark.parametrize("builder,variant,key", [
    (demo.build_pe32, "32", demo.KEY32),
    (demo.build_pe64, "64", demo.KEY64),
])
def test_stealc_example(tmp_path, builder, variant, key):
    sample = tmp_path / "s.exe"
    sample.write_bytes(builder())
    res = Engine(EX / "rule.yar", EX / "plugin.py").run(sample)

    assert res["status"] == "success", res
    assert [e["variant"] for e in res["config"]] == [variant] * 3
    assert [e["config"] for e in res["config"]] == [s.decode() for s in demo.STRINGS]
    assert all(e["inputs"]["key"]["value"] == key for e in res["config"])
    assert all(e["inputs"]["data"]["section"] == ".rdata" for e in res["config"])


def test_stealc_locate_mode_shows_every_reference(tmp_path):
    sample = tmp_path / "s.exe"
    sample.write_bytes(demo.build_pe64())
    res = Engine(EX / "rule.yar").run(sample)          # no plugin
    cfg = res["config"][0]["config"]
    assert cfg["key_64"] == demo.KEY64
    assert len(cfg["data_64"]) == 3
    assert set(cfg) == {"key_64", "data_64"}           # `extract` meta hides the s*/m* strings
