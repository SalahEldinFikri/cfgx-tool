from pathlib import Path

import pytest

import kittysocks5_demo as demo
from cfgx import Engine
from cfgx.output import auto_parse

EX = Path(__file__).resolve().parent.parent / "examples" / "kittysocks5"


def run(tmp_path, data, rule=None, name="s.elf"):
    p = tmp_path / name
    p.write_bytes(data)
    return Engine(rule or EX / "rule.yar", EX / "plugin.py").run(p)


def test_one_rule_file_runs_every_rule_and_picks_the_right_one(tmp_path):
    for data, rule_name in ((demo.build(), "kittysocks5"), (demo.build_v2(), "kittysocks5_v2"),
                            (demo.build_mips(), "kittysocks5_Mips_Version")):
        res = run(tmp_path, data)
        assert res["status"] == "success", res
        assert res["rules"] == [rule_name]
        assert res["families"] == ["kittysocks5"]                 # FAMILY in the plugin: one folder


def test_arm_v2_config_and_config2_both_extracted(tmp_path):
    res = run(tmp_path, demo.build_v2())
    by_variant = {}
    for e in res["config"]:
        by_variant.setdefault(e.get("variant"), []).append(e)
    # $config -> plain entries, $config2 -> variant "2": sizes come from R2 in both patterns
    assert [e["config"] for e in by_variant[None]] == [auto_parse(p) for p in demo.V2_CONFIG]
    assert [e["config"] for e in by_variant["2"]] == [auto_parse(p) for p in demo.V2_CONFIG2]
    assert all(e["inputs"]["key"]["value"] == demo.KEY2 for e in res["config"])
    assert not [w for w in res["warnings"] if "size" in w]


def test_config2_inherits_the_config_meta(tmp_path):
    # no config2_* lines in the rule: config2 must use config_size_reg / config_ref_index
    from cfgx.engine import Engine as E
    class Hit:   # minimal stand-in for a rule hit
        meta = {"config_size_reg": "r2", "key_size": 16}
    assert E._m(Hit, "config2", "size_reg") == "r2"
    assert E._m(Hit, "config_v2", "size_reg") == "r2"
    assert E._m(Hit, "key_32", "size") == 16
    assert E._m(Hit, "other", "size_reg") is None


@pytest.mark.parametrize("gp_via", ["phdr", "reginfo", "got"])
def test_mips_pic_all_ways_of_finding_gp(tmp_path, gp_via):
    res = run(tmp_path, demo.build_mips(gp_via))
    assert res["status"] == "success", res
    assert res["sample"]["arch"] == "mips" and res["sample"]["endian"] == "big"
    assert [e["config"] for e in res["config"]] == [auto_parse(p) for p in demo.M_PLAIN]
    assert [e["inputs"]["data"]["size"] for e in res["config"]] == demo.M_SIZES   # li $a2,N, per entry
    assert res["config"][0]["inputs"]["key"]["value"] == demo.M_KEY               # via the GOT, key_size = 16
    assert res["config"][0]["inputs"]["data"]["via"] == "ref:gp+addiu"
    assert res["config"][0]["inputs"]["key"]["via"] == "ref:gp-got"


def test_mips_without_gp_explains_and_the_rule_meta_fixes_it(tmp_path):
    res = run(tmp_path, demo.build_mips("none"))
    assert res["config"] == []
    assert any("$gp value is unknown" in w and "mips_gp" in w for w in res["warnings"])

    fixed = tmp_path / "fixed.yar"
    fixed.write_text((EX / "rule.yar").read_text().replace(
        "// mips_gp = 0x4a0ff0", f"mips_gp = {demo.M_GP:#x}"))
    res = run(tmp_path, demo.build_mips("none"), rule=fixed, name="s2.elf")
    assert res["status"] == "success" and len(res["config"]) == 6


def test_mips_all_references_still_gives_the_same_entries(tmp_path):
    # with "all", the function pointer built for `jalr $t9` is followed too, but no size can be
    # recovered for it, so it yields no entry - only a verbose-only note
    rule = tmp_path / "all.yar"
    rule.write_text((EX / "rule.yar").read_text().replace("config_ref_index = 0 ", 'config_ref_index = "all"'))
    res = run(tmp_path, demo.build_mips(), rule=rule)
    assert len(res["config"]) == 6
    skipped = [w for w in res["warnings"] if "could not recover the size" in w]
    assert skipped and all("[note]" in w for w in skipped)


def test_code_matches_are_never_read_as_data(tmp_path):
    # Regression: with $gp unknown the instruction bytes themselves were decrypted and reported as "entries".
    res = run(tmp_path, demo.build_mips("none"))
    assert res["status"] == "failed" and res["config"] == []


def test_mips_register_names_are_checked(tmp_path):
    bad = tmp_path / "bad.yar"
    bad.write_text((EX / "rule.yar").read_text().replace('config_size_reg  = "a2"', 'config_size_reg  = "li"'))
    res = run(tmp_path, demo.build_mips(), rule=bad)
    assert any("unknown MIPS register 'li'" in w and "a2" in w for w in res["warnings"])
