import json
from pathlib import Path

import stealc_demo as stealc
from builders import build_pe
from cfgx import Engine
from cfgx.cli import main
from cfgx.export import UNMATCHED, safe_name, save_directory
from cfgx.formats import load_image
from cfgx.render import Console

EX = Path(__file__).resolve().parent.parent / "examples" / "stealc"


def run_all(tmp_path, *builders_and_names):
    eng = Engine(EX / "rule.yar", EX / "plugin.py")
    results = []
    for name, data in builders_and_names:
        p = tmp_path / name
        p.parent.mkdir(exist_ok=True)
        p.write_bytes(data)
        results.append(eng.run(p))
    return results


def files(root: Path):
    return sorted(str(p.relative_to(root)).replace("\\", "/") for p in root.rglob("*") if p.is_file())


def test_family_directory_layout(tmp_path):
    results = run_all(tmp_path, ("a.exe", stealc.build_pe32()), ("b.exe", stealc.build_pe64()),
                      ("junk.bin", b"nothing to see"))
    out = tmp_path / "out"
    info = save_directory(results, out)

    assert files(out) == sorted([
        "Stealc/a.exe.cfgx.json", "Stealc/b.exe.cfgx.json", "Stealc/Stealc.family.json",
        f"{UNMATCHED}/junk.bin.cfgx.json", "summary.json"])
    assert info["total"] == 5                       # one per sample + one for the family + summary
    assert info["layout"][-1] == "summary.json"


def test_family_file_covers_the_whole_family(tmp_path):
    results = run_all(tmp_path, ("a.exe", stealc.build_pe32()), ("b.exe", stealc.build_pe64()))
    out = tmp_path / "out"
    save_directory(results, out)
    doc = json.loads((out / "Stealc" / "Stealc.family.json").read_text())

    assert doc["schema"] == "cfgx-family/1" and doc["family"] == "Stealc"
    assert [s["name"] for s in doc["samples"]] == ["a.exe", "b.exe"]
    assert all(s["entries"] == 3 and s["status"] == "success" for s in doc["samples"])
    assert len(doc["results"]) == 2
    texts = {k["text"] for k in doc["keys"]}
    assert texts == {stealc.KEY32.decode(), stealc.KEY64.decode()}       # keys seen across the family
    assert all(k["samples"] == 1 for k in doc["keys"])


def test_family_file_is_merged_across_runs(tmp_path):
    out = tmp_path / "out"
    r1 = run_all(tmp_path, ("a.exe", stealc.build_pe32()))
    save_directory(r1, out)
    r2 = run_all(tmp_path, ("b.exe", stealc.build_pe64()))
    save_directory(r2, out)
    doc = json.loads((out / "Stealc" / "Stealc.family.json").read_text())
    assert [s["name"] for s in doc["samples"]] == ["a.exe", "b.exe"]      # first run kept

    save_directory(r2, out)                                                # same sha256 again: replaced
    doc = json.loads((out / "Stealc" / "Stealc.family.json").read_text())
    assert len(doc["results"]) == 2


def test_failed_sample_is_still_filed_under_its_family(tmp_path):
    # rule matched but nothing decrypted -> no config entries, yet the family is known
    res = {"sample": {"name": "bad.exe", "path": "bad.exe", "sha256": "ab" * 32}, "status": "failed",
           "rules": ["StealcStealer"], "families": ["Stealc"], "config": [], "warnings": [], "errors": ["x"]}
    out = tmp_path / "out"
    save_directory([res], out)
    assert (out / "Stealc" / "bad.exe.cfgx.json").exists()


def test_unsafe_family_names_become_safe_directories(tmp_path):
    assert safe_name('Bad:/Name?') == "Bad__Name_"
    assert safe_name("  ..  ") == "unknown"
    res = {"sample": {"name": "x", "path": "x", "sha256": "cd" * 32}, "status": "success", "rules": ["r"],
           "families": ['We<ird>:"Family'], "config": [], "warnings": [], "errors": []}
    out = tmp_path / "out"
    save_directory([res], out)
    assert (out / "We_ird___Family").is_dir()


def test_same_file_name_from_two_folders_does_not_overwrite(tmp_path):
    results = run_all(tmp_path, ("x/s.exe", stealc.build_pe32()), ("y/s.exe", stealc.build_pe64()))
    out = tmp_path / "out"
    save_directory(results, out)
    assert len([f for f in files(out) if f.startswith("Stealc/") and f.endswith("s.exe.cfgx.json")]) == 2


def test_cli_o_directory_and_summary_line(tmp_path, capsys):
    s = tmp_path / "samples"
    s.mkdir()
    (s / "a.exe").write_bytes(stealc.build_pe32())
    (s / "b.exe").write_bytes(stealc.build_pe64())
    out = tmp_path / "res"
    code = main([str(EX / "rule.yar"), str(s), str(EX / "plugin.py"), "-o", str(out), "--color", "never"])
    text = capsys.readouterr().out
    assert code == 0
    assert "saved 4 files to" in text and "Stealc" in text and "Stealc.family.json" in text
    assert (out / "Stealc" / "Stealc.family.json").exists()


# ------------------------------------------------------------------ the bugs seen in the field
def test_more_than_256_strings_are_all_extracted(tmp_path, monkeypatch):
    # Regression: data/key combinations were capped at 256, silently cutting off real entries.
    monkeypatch.setattr(stealc, "STRINGS", [f"string-number-{i:04d}".encode() for i in range(400)])
    p = tmp_path / "big.exe"
    p.write_bytes(stealc.build_pe32())
    res = Engine(EX / "rule.yar", EX / "plugin.py").run(p)
    assert res["status"] == "success"
    assert len(res["config"]) == 400
    assert not any("combinations" in w for w in res["warnings"])


def test_references_into_empty_buffers_are_only_notes(tmp_path):
    # with ref_index = "all", references that point at zeroed buffers are expected, not warnings
    text = b"\x90\x68" + (0x402000 + 0x20).to_bytes(4, "little") + b"\x90" * 4
    blob, _ = build_pe(text, b"hello\x00" + b"\x00" * 64, bits=32)
    p = tmp_path / "e.exe"
    p.write_bytes(blob)
    rule = tmp_path / "r.yar"
    rule.write_text('rule N { meta: d_ref_index = "all" strings: $d = { 68 ?? ?? ?? ?? } condition: $d }')
    res = Engine(rule).run(p)
    empties = [w for w in res["warnings"] if "nothing readable" in w]
    assert empties and all("[note]" in w for w in empties)
    buf = __import__("io").StringIO()
    Console(stream=buf, color="never").sample(res)
    assert "nothing readable" not in buf.getvalue()


def test_many_similar_warnings_collapse_to_one_line():
    res = {"status": "success", "sample": {"name": "s", "format": "pe", "arch": "x64"}, "config": [],
           "errors": [], "detections": [],
           "warnings": [f"R: $data_64: something odd at {hex(0xb7000 + i * 0x20)}" for i in range(300)]}
    buf = __import__("io").StringIO()
    Console(stream=buf, color="never", width=120).sample(res)
    out = buf.getvalue()
    assert out.count("something odd") == 1 and "(+299 similar)" in out


def test_raw_fallback_says_why(tmp_path, monkeypatch):
    rule = tmp_path / "r.yar"
    rule.write_text('rule X { strings: $a = "MZ" condition: $a }')
    fake = tmp_path / "fake.bin"
    fake.write_bytes(b"MZ" + b"\x00" * 200)                                   # MZ but no PE signature
    res = Engine(rule).run(fake)
    assert any("no valid PE signature" in w for w in res["warnings"])

    import cfgx.formats as formats

    real = tmp_path / "real.exe"
    real.write_bytes(stealc.build_pe32())
    monkeypatch.setattr(formats, "load_pe", lambda path: (_ for _ in ()).throw(ValueError("corrupt optional header")))
    res = Engine(rule).run(real)
    assert any("PE headers found but they could not be parsed (ValueError: corrupt optional header)" in w
               for w in res["warnings"])
    assert res["sample"]["format"] == "raw"


def test_console_never_prints_raw_control_characters():
    # Regression: a C1 code such as 0x9B acts as an ANSI escape in some terminals and made a table row vanish.
    c = Console(stream=__import__("io").StringIO(), color="never", width=100)
    out = c.fmt_value("a\x9bb\x85c\u2028d\x1be\x7ff", 80)
    assert all(ch.isprintable() for ch in out)
    assert "\\x9b" in out and "\\u2028" in out and "\\x1b" in out
