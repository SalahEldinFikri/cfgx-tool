import io
from pathlib import Path

import kittysocks5_demo as kitty
import stealc_demo as stealc
from cfgx import Engine
from cfgx.cli import main
from cfgx.render import Console

EX = Path(__file__).resolve().parent.parent / "examples"


def render(res, **kw):
    buf = io.StringIO()
    Console(stream=buf, color="never", width=100).sample(res, **kw)
    return buf.getvalue()


def stealc_result(tmp_path):
    p = tmp_path / "s.exe"
    p.write_bytes(stealc.build_pe32())
    return Engine(EX / "stealc/rule.yar", EX / "stealc/plugin.py").run(p)


def test_table_has_key_once_and_all_rows(tmp_path):
    out = render(stealc_result(tmp_path))
    assert "Stealc" in out and "3 entries" in out
    assert out.count("A1b2C3d4E5f6G7h8I9") == 1           # key shown once, not per row
    assert "http://203.0.113.7" in out and "var" in out and "offset" in out
    assert '"http' not in out                              # no JSON quoting of plain strings


def test_binary_values_are_previewed_not_dumped(tmp_path):
    p = tmp_path / "k.elf"
    p.write_bytes(kitty.build())
    res = Engine(EX / "kittysocks5/rule.yar", EX / "kittysocks5/plugin.py").run(p)
    out = render(res)
    assert "(1500 B)" in out and "udp:8080" in out
    assert out.count("(16 B)") == 1                        # key size printed once
    assert max(len(line) for line in out.splitlines()) <= 100


def test_no_match_is_silent_unless_verbose(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"nothing")
    res = Engine(EX / "stealc/rule.yar").run(p)
    assert render(res) == ""
    assert "no rule matched" in render(res, verbose=True)


def test_note_warnings_hidden_until_verbose(tmp_path):
    p = tmp_path / "f.exe"
    import ffdroider_demo
    p.write_bytes(ffdroider_demo.build())
    res = Engine(EX / "ffdroider/rule.yar", EX / "ffdroider/plugin.py").run(p)
    assert "read up to the first NUL" not in render(res)
    assert "read up to the first NUL" in render(res, verbose=True)


def test_colour_only_when_asked():
    buf = io.StringIO()
    Console(stream=buf, color="always").line(Console(stream=buf, color="always").st("x", "green"))
    assert "\x1b[32m" in buf.getvalue()
    buf2 = io.StringIO()
    c = Console(stream=buf2, color="never")
    assert c.st("x", "green") == "x"


def test_ascii_fallback_when_stream_cannot_do_unicode(tmp_path):
    class Ascii(io.StringIO):
        encoding = "cp1252"
    buf = Ascii()
    Console(stream=buf, color="never", width=100).sample(stealc_result(tmp_path))
    buf.getvalue().encode("cp1252")                         # must not raise


def test_cli_summary_and_exit_codes(tmp_path, capsys):
    s = tmp_path / "s"
    s.mkdir()
    (s / "a.exe").write_bytes(stealc.build_pe32())
    (s / "b.bin").write_bytes(b"junk")
    code = main([str(EX / "stealc/rule.yar"), str(s), str(EX / "stealc/plugin.py"), "--color", "never"])
    out = capsys.readouterr().out
    assert code == 0
    assert "2 scanned" in out and "1 extracted" in out and "1 no match" in out
    assert "b.bin" not in out                               # unmatched files are not listed
    main([str(EX / "stealc/rule.yar"), str(s), str(EX / "stealc/plugin.py"), "--color", "never", "-v"])
    assert "b.bin" in capsys.readouterr().out
