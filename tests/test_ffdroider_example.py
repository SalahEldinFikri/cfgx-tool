from pathlib import Path

import ffdroider_demo as demo
from cfgx import Engine

EX = Path(__file__).resolve().parent.parent / "examples" / "ffdroider"


def test_ffdroider_both_patterns(tmp_path):
    sample = tmp_path / "f.exe"
    sample.write_bytes(demo.build())
    res = Engine(EX / "rule.yar", EX / "plugin.py").run(sample)

    assert res["status"] == "success", res
    by_variant = {}
    for e in res["config"]:
        by_variant.setdefault(e.get("variant"), []).append(e["config"])
    assert by_variant[None] == [s.decode() for s in demo.DATA_STRINGS]       # $data
    assert by_variant["2"] == [s.decode() for s in demo.DATA2_STRINGS]       # $data2
    assert all(e["inputs"]["data"]["via"] == "ref:push" for e in res["config"])


def test_old_legacy_plugin_style_still_gets_the_same_strings(tmp_path):
    """Sanity check of the compatibility path with the plugin the analyst used before."""
    legacy = tmp_path / "old.py"
    legacy.write_text('''
def decrypt(data):
    return bytes(b ^ (i % 18 + 5) for i, b in enumerate(data))

def extract(matches, reader):
    out = []
    for m in matches:
        if m["identifier"] not in ("$data", "$data2"):
            continue
        for r in m.get("references", [])[:1]:
            d = r["data"].split(b"\\x00", 1)[0]
            out.append(decrypt(d).decode())
    return {"status": "success", "config": out}
''')
    sample = tmp_path / "f.exe"
    sample.write_bytes(demo.build())
    res = Engine(EX / "rule.yar", legacy).run(sample)
    assert any("defines both extract() and decrypt()" in w for w in res["warnings"])
    got = [x for e in res["config"] for x in e["config"]]
    assert sorted(got) == sorted(s.decode() for s in demo.DATA_STRINGS + demo.DATA2_STRINGS)
