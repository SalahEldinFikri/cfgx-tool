import importlib.util
import random
from pathlib import Path

import aisuru_demo as demo
from cfgx import Engine
from cfgx.formats import load_image
from cfgx.output import auto_parse
from cfgx.reader import Reader
from cfgx.refs import find_references

EX = Path(__file__).resolve().parent.parent / "examples" / "aisuru"


def plugin_module():
    spec = importlib.util.spec_from_file_location("aisuru_plugin", EX / "plugin.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def run(tmp_path, data, name="s"):
    p = tmp_path / name
    p.write_bytes(data)
    return Engine(EX / "rule.yar", EX / "plugin.py").run(p)


def test_v2_cipher_equals_the_literal_transcription_of_the_decompiled_routine():
    mod, rnd = plugin_module(), random.Random(11)
    for _ in range(120):
        key = bytes(rnd.randrange(256) for _ in range(rnd.choice([1, 7, 16, 16, 31])))
        data = bytes(rnd.randrange(256) for _ in range(rnd.choice([0, 1, 9, 50, 142, 700])))
        assert mod.v2_crypt(data, key) == demo.literal_three(data, key)


def test_x86_v1_rc4_entries(tmp_path):
    res = run(tmp_path, demo.build_x86_v1())
    assert res["status"] == "success", res
    assert res["rules"] == ["AISURU"] and res["families"] == ["AISURU"]
    assert [e["config"] for e in res["config"]] == [auto_parse(p) for p in demo.V1_ENTRIES]
    assert [e["inputs"]["data"]["size"] for e in res["config"]] == [len(p) for p in demo.V1_ENTRIES]
    assert all(e["inputs"]["key"]["value"] == demo.KEY1 for e in res["config"])


def test_x86_v2_blobs_with_tails_and_key_through_a_pointer_variable(tmp_path):
    res = run(tmp_path, demo.build_x86_v2())
    assert res["status"] == "success", res
    assert res["rules"] == ["AISURU_V2"]
    blobs = [e for e in res["config"] if e.get("variant") is None]       # $config: rep movsd copies
    blobs2 = [e for e in res["config"] if e.get("variant") == "2"]       # $config2: push len / push blob
    # $key: `mov edx,[abs32]` gives the pointer VARIABLE, key_deref follows it to the string
    assert blobs[0]["inputs"]["key"]["value"] == demo.KEY2
    assert blobs[0]["inputs"]["key"]["via"] == "ref:mov-mem->ptr"
    # sizes are EXACT: DWORDS * 4 + the movsw (2) / movsb (1) tail; lengths 27, 21, 19, 32 cover every tail case
    assert [e["inputs"]["data"]["size"] for e in blobs] == [len(p) for p in demo.V2_CONFIG]
    assert [e["config"] for e in blobs] == [auto_parse(p) for p in demo.V2_CONFIG]
    # $config2: push imm8 and push imm32 (>127 bytes), and the *4 of $config must not leak into it
    assert [e["inputs"]["data"]["size"] for e in blobs2] == [len(p) for p in demo.V2_BLOBS]
    assert [e["config"] for e in blobs2] == [auto_parse(p) for p in demo.V2_BLOBS]


def test_size_tail_adds_the_movsw_movsb_bytes():
    from cfgx.engine import Engine as E
    pre = b"\xBE\x00\x00\x00\x00\xB9\x07\x00\x00\x00\xF3\xA5"
    spec = "F3A5 66A5=2 A4=1"
    assert E._tail_bytes(spec, pre + b"\x66\xA5\xA4\xA1", 6) == 3
    assert E._tail_bytes(spec, pre + b"\x66\xA5\xA1", 6) == 2
    assert E._tail_bytes(spec, pre + b"\xA4\xA1", 6) == 1
    assert E._tail_bytes(spec, pre + b"\xA1", 6) == 0
    assert E._tail_bytes(spec, b"\x90" * 12, 6) == 0                 # no `rep movsd`: nothing is added


def test_auto_reports_which_algorithm_it_picked(tmp_path):
    auto = tmp_path / "auto.yar"
    auto.write_text((EX / "rule.yar").read_text().replace(
        'algo               = "aisuru_v2"   // key schedule sub_804D070 + the custom PRGA (verified on real samples)',
        'algo               = "auto"'))
    p = tmp_path / "v2"
    p.write_bytes(demo.build_x86_v2())
    res = Engine(auto, EX / "plugin.py").run(p)
    notes = [w for w in res["warnings"] if "[note]" in w and "algo=auto picked" in w]
    assert notes and all("aisuru_v2" in w for w in notes)             # the custom cipher is the readable one
    res = run(tmp_path, demo.build_arm(), name="arm")
    assert any("algo=auto picked rc4" in w for w in res["warnings"])  # ARM sample: plain RC4 gives the text


def test_arm_bss_state_buffer_does_not_shift_the_reference_index(tmp_path):
    res = run(tmp_path, demo.build_arm(), name="arm")
    assert res["status"] == "success", res
    assert res["rules"] == ["AISURU_ARM_V"]
    assert [e["config"] for e in res["config"]] == [auto_parse(p) for p in demo.ARM_ENTRIES]
    assert all(e["inputs"]["data"]["size"] == 16 for e in res["config"])
    assert res["config"][0]["inputs"]["key"]["value"] == demo.ARM_KEY
    # R0 points into .bss: kept as a placeholder, so "the 2nd literal load" is always the 2nd instruction
    p = tmp_path / "arm"
    image = load_image(p)
    code = p.read_bytes()
    with Reader(p, image) as r:
        refs = find_references(image, 0x100, code[0x100:0x110], r.read)
    image.close()
    assert [x["offset"] is None for x in refs] == [True, False]


def test_a_pointer_that_leads_nowhere_is_reported_not_guessed(tmp_path):
    res = run(tmp_path, demo.build_x86_v2(ptr_to_key=False))
    assert not [e for e in res["config"] if e.get("inputs", {}).get("key")]
    assert any("does not lead into the image" in w for w in res["warnings"])


def test_one_run_over_all_three_architectures_one_family_folder(tmp_path):
    from cfgx.export import save_directory
    eng = Engine(EX / "rule.yar", EX / "plugin.py")
    results = []
    for name, data in (("v1", demo.build_x86_v1()), ("v2", demo.build_x86_v2()), ("arm", demo.build_arm())):
        p = tmp_path / name
        p.write_bytes(data)
        results.append(eng.run(p))
    assert [r["status"] for r in results] == ["success"] * 3
    out = tmp_path / "out"
    save_directory(results, out)
    assert sorted(f.name for f in (out / "AISURU").iterdir()) == [
        "AISURU.family.json", "arm.cfgx.json", "v1.cfgx.json", "v2.cfgx.json"]


def test_arm_with_a_real_section_table_keeps_bss_so_ref_index_is_stable(tmp_path):
    # Regression (real ARM sample): with section headers, .bss was dropped from the image, the placeholder for
    # `LDR R0,=ctx` vanished and "key_ref_index=1 but only 1 reference(s) found" followed.
    res = run(tmp_path, demo.build_arm(sections=True), name="arm_sections")
    assert res["status"] == "success", res
    assert [e["config"] for e in res["config"]] == [auto_parse(p) for p in demo.ARM_ENTRIES]
    assert not [w for w in res["warnings"] if "only 1 reference" in w]


def test_elf_bss_section_is_mapped_but_has_no_file_bytes(tmp_path):
    p = tmp_path / "arm"
    p.write_bytes(demo.build_arm(sections=True))
    image = load_image(p)
    bss = next(m for m in image.mappings if m.name == ".bss")
    assert bss.file_size == 0 and bss.mem_size > 0
    assert image.mapping_at_va(bss.va) is bss and image.va_to_offset(bss.va) is None
    image.close()


def test_noise_is_reported_when_nothing_decrypts_to_text(tmp_path):
    # Regression: on a real v2 sample the cipher was wrong, yet 16 hex rows were printed as if they were results.
    rule = tmp_path / "wrong.yar"
    rule.write_text((EX / "rule.yar").read_text().replace(
        'algo               = "aisuru_v2"   // key schedule sub_804D070 + the custom PRGA (verified on real samples)',
        'algo               = "rc4"'))
    p = tmp_path / "v2"
    p.write_bytes(demo.build_x86_v2())
    res = Engine(rule, EX / "plugin.py").run(p)
    assert any("none of the 4 entries decrypted to readable text" in w for w in res["warnings"])
    assert all(e.get("confidence") == "low" for e in res["config"])
    # ... and a correct decryption stays quiet
    good = run(tmp_path, demo.build_x86_v2(), name="v2good")
    assert not [w for w in good["warnings"] if "readable text" in w and "none of" in w]
    assert all("confidence" not in e for e in good["config"])


# --- ground truth taken from REAL samples (x86 v2, 7bc264b4...), independent of this code base
REAL_KEY = b"PJbiNbbeasddDfsc"
# What the real v2 sample's first 24 ciphertext bytes looked like after PLAIN RC4 had (wrongly) been applied in a real run,
# and the text they really are. Undoing that RC4 layer gives back the raw ciphertext bytes.
REAL_AFTER_PLAIN_RC4 = {
    "GET / HTTP/1.1\r\nHost: ?\r": "66b18835202953bd62fa9be8c4287a38a2412627f59b2977",
    "POST ? HTTP/1.1\r\nHost: ?":   "71bb8f412f363ba162fee4f6db37463fe0663a20bb813645",
    "wget,curl,tftp,ftp,mount":       "5693b961236a6e9b5a86c0bf9e695b549e5e793ea0ce780e",
    "telnetd,udhcpc,inetd,ntp":       "5591b07b6a7d7fc543cedcba9a7a5b5b844b2137e3d5620a",
    "System upgrade in progre":       "728daf616a643b9c46cdc6b88e7c575b840e2521a0dc641f",
    "/proc/self/oom_score_adj":       "0e84ae7a6c26688c5acc9bb6857428418941273690da7210",
}


def test_v2_keystream_equals_the_one_recovered_from_real_samples():
    # recovered by XOR-ing real entries and cribbing a known plaintext (an alphabet string)
    assert plugin_module().v2_crypt(bytes(24), REAL_KEY).hex() == "7ded2d4c0dba1a7c16d82a4e9c2061c12e01dbf9a7a3ace3"


def test_v2_decrypts_real_ciphertext():
    from cfgx.crypto import rc4
    mod = plugin_module()
    for plain, shown in REAL_AFTER_PLAIN_RC4.items():
        raw = rc4(bytes.fromhex(shown), REAL_KEY)             # undo the plain-RC4 layer to get the raw ciphertext
        assert mod.v2_crypt(raw, REAL_KEY).decode("latin-1") == plain


def test_unencrypted_table_entries_are_left_alone(tmp_path):
    res = run(tmp_path, demo.build_x86_v2())
    last = [e for e in res["config"] if e.get("variant") == "2"][-1]
    assert last["config"] == auto_parse(b"\r\n")             # stored in clear (flag byte 0): not "decrypted" into noise
