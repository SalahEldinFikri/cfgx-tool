"""Terminal output for the cfgx CLI.  Pure standard library: colour and Unicode are used
only when the terminal supports them and fall back to plain ASCII otherwise."""
from __future__ import annotations

import json
import os
import re
import shutil
import sys
import textwrap
from typing import Any, Dict, List

from . import __version__
from .output import decode_text, to_jsonable

_CODES = {"bold": "1", "dim": "2", "red": "31", "green": "32", "yellow": "33",
          "cyan": "36", "gray": "90"}
_NOTE = "[note]"


def _enable_windows_vt() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        handle = k32.GetStdHandle(-11)
        mode = ctypes.c_ulong()
        if not k32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(k32.SetConsoleMode(handle, mode.value | 0x0004))
    except Exception:
        return False


def human_size(n) -> str:
    if not isinstance(n, int):
        return ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return ""


class Console:
    def __init__(self, stream=None, color="auto", full=False, width=None):
        self.out = stream or sys.stdout
        tty = bool(getattr(self.out, "isatty", lambda: False)())
        if color == "always":
            _enable_windows_vt()
            self.color = True
        elif color == "never":
            self.color = False
        else:
            self.color = (tty and "NO_COLOR" not in os.environ
                          and os.environ.get("TERM") != "dumb" and _enable_windows_vt())
        enc = (getattr(self.out, "encoding", None) or "").lower()
        self.unicode = "utf" in enc
        cols = width or shutil.get_terminal_size((100, 24)).columns
        self.width = max(60, min(cols, 160))
        self.full = full
        u = self.unicode
        self.S = {
            "ok": "✔" if u else "+", "bad": "✘" if u else "x", "warn": "▲" if u else "!",
            "dot": "·" if u else "-", "rule": "─" if u else "-", "ell": "…" if u else "...",
            "arrow": "→" if u else "->",
        }

    # ---------------------------------------------------------------- basics
    def st(self, text: str, *styles: str) -> str:
        if not self.color or not styles:
            return text
        return f"\x1b[{';'.join(_CODES[s] for s in styles)}m{text}\x1b[0m"

    def line(self, text: str = "") -> None:
        print(text, file=self.out)

    def fit(self, s: str, width: int) -> str:
        if self.full or len(s) <= width:
            return s
        e = self.S["ell"]
        return s[: max(1, width - len(e))] + e

    def hr(self, indent: int = 2) -> str:
        return " " * indent + self.st(self.S["rule"] * (self.width - indent * 2), "gray")

    # ---------------------------------------------------------------- values
    def fmt_value(self, v: Any, limit: int = 80) -> str:
        if isinstance(v, (bytes, bytearray)):
            b = bytes(v)
            text = decode_text(b)
            if text is not None:
                s = text
            else:
                preview = b[:24].hex()
                s = f"{preview}{self.S['ell'] if len(b) > 24 else ''}  ({len(b)} B)"
        elif isinstance(v, str):
            s = v
        elif v is None:
            s = "null"
        else:
            s = json.dumps(to_jsonable(v), ensure_ascii=False, separators=(", ", ": "))
        s = s.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
        s = "".join(ch if ch.isprintable() else
                    ("\\x%02x" % ord(ch) if ord(ch) < 256 else "\\u%04x" % ord(ch)) for ch in s)
        return self.fit(s, limit)

    # ---------------------------------------------------------------- table
    def table(self, headers: List[str], rows: List[List[str]], aligns: str, styles: List[tuple],
              indent: int = 4) -> None:
        """Last column is flexible and truncated to the terminal width."""
        gap = 2
        widths = [len(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r[:-1]):
                widths[i] = max(widths[i], len(c))
        used = indent + sum(widths[:-1]) + gap * (len(headers) - 1)
        last = max(12, self.width - used - 1)

        def fmt(cells, hdr=False):
            out = []
            for i, c in enumerate(cells):
                c = self.fit(c, last) if i == len(cells) - 1 else c
                if i == len(cells) - 1:
                    cell = c
                else:
                    cell = c.rjust(widths[i]) if aligns[i] == "r" else c.ljust(widths[i])
                out.append(self.st(cell, "dim") if hdr else self.st(cell, *styles[i]))
            return " " * indent + (" " * gap).join(out)

        self.line(fmt(headers, hdr=True))
        for r in rows:
            self.line(fmt(r))

    # ---------------------------------------------------------------- pieces
    def banner(self, rule, plugin, n_files):
        parts = [self.st(f"cfgx {__version__}", "bold"), f"rule {rule}"]
        parts.append(f"plugin {os.path.basename(str(plugin))}" if plugin else "no plugin (read values as-is)")
        parts.append(f"{n_files} file{'s' if n_files != 1 else ''}")
        self.line(self.st(f" {self.S['dot']} ", "gray").join(parts))
        self.line()

    def _meta_line(self, s: dict) -> str:
        sha = s.get("sha256") or ""
        bits = [f"{s.get('format', '?')}/{s.get('arch') or '?'}", human_size(s.get("size")),
                f"sha256 {sha[:8]}{self.S['ell']}{sha[-6:]}" if sha else ""]
        return (f" {self.S['dot']} ").join(b for b in bits if b)

    def sample(self, res: dict, verbose: bool = False) -> None:
        status, s = res["status"], res["sample"]
        if status == "no_match":
            if verbose:
                self.line(f"  {self.st(self.S['dot'], 'gray')} " + self.st(
                    f"{s.get('name')}   {s.get('format', '?')}   no rule matched", "gray"))
            return

        ok = status in ("success", "located")
        if ok:
            mark = self.st(self.S["ok"], "green", "bold")
        elif status == "detected":
            mark = self.st(self.S["dot"] if not self.unicode else "◆", "cyan", "bold")
        else:
            mark = self.st(self.S["bad"], "red", "bold")
        self.line(f"{mark} {self.st(s.get('name', '?'), 'bold')}")
        meta = self._meta_line(s)
        if not ok and status != "detected":
            meta += f" {self.S['dot']} {status}"
        self.line("  " + self.st(meta, "dim"))
        if res.get("detections"):
            label = "detected" if ok else "family detected, no configuration extracted:"
            self.line("  " + self.st(label, "cyan") + " " + ", ".join(res["detections"]))

        groups: Dict[str, List[dict]] = {}
        for e in res["config"]:
            groups.setdefault(e["rule"], []).append(e)
        for rule, entries in groups.items():
            self.line()
            self._group(rule, entries)
        self._notes(res, verbose)
        self.line()

    def _group(self, rule: str, entries: List[dict]) -> None:
        fam = entries[0].get("family") or rule
        title = fam if fam == rule else f"{fam} ({rule})"
        n = len(entries)
        count = f"{n} {'entry' if n == 1 else 'entries'}"
        self.line("  " + self.st(title, "cyan", "bold") + "  " + self.st(count, "dim"))
        self.line(self.hr())
        first = entries[0]
        if "inputs" in first:
            self._decrypted(entries)
        elif "located" in first:
            self._located(first)
        else:
            self._legacy(entries)

    def _decrypted(self, entries: List[dict]) -> None:
        # keys / IVs used (shown once each)
        seen = set()
        for e in entries:
            for param, t in e["inputs"].items():
                if param == "data" or "value" not in t:
                    continue
                ident = (param, t["value"])
                if ident in seen:
                    continue
                seen.add(ident)
                raw = t["value"]
                val = (decode_text(raw) if isinstance(raw, bytes) else None) or (
                    raw.hex() if isinstance(raw, bytes) else str(raw))
                val = self.fit(val, 64)
                where = f"@{t['offset']:#x} {t.get('section') or ''}".rstrip()
                self.line("    " + self.st(param.ljust(5), "yellow") + " " + val + "  "
                          + self.st(f"({t['size']} B) {where}", "dim"))
        if seen:
            self.line()

        structured = any(isinstance(e["config"], (dict, list)) for e in entries)
        has_var = any(e.get("variant") for e in entries)
        if structured:
            for i, e in enumerate(entries, 1):
                d = e["inputs"].get("data", {})
                var = f" [{e['variant']}]" if e.get("variant") else ""
                self.line("    " + self.st(f"#{i}{var}  @{d.get('offset', 0):#x} {d.get('section') or ''}", "gray"))
                self._kv(e["config"], 8)
            return

        headers = ["#"] + (["var"] if has_var else []) + ["offset", "section", "size", "value"]
        aligns = "r" + ("l" if has_var else "") + "llrl"
        styles = [("dim",)] + ([()] if has_var else []) + [("gray",), ("gray",), ("gray",), ()]
        rows = []
        for i, e in enumerate(entries, 1):
            d = e["inputs"].get("data", {})
            row = [str(i)]
            if has_var:
                row.append(str(e.get("variant") or "-"))
            row += [f"{d.get('offset', 0):#x}", d.get("section") or "-", str(d.get("size", "")),
                    "\0"]
            rows.append(row)
        self._with_values(headers, rows, aligns, styles, [e["config"] for e in entries])

    def _with_values(self, headers, rows, aligns, styles, values):
        # value column limit depends on the other columns, so fill it in after measuring
        widths = [len(h) for h in headers]
        for r in rows:
            for i, c in enumerate(r[:-1]):
                widths[i] = max(widths[i], len(c))
        limit = max(12, self.width - (4 + sum(widths[:-1]) + 2 * (len(headers) - 1)) - 1)
        for r, v in zip(rows, values):
            r[-1] = self.fmt_value(v, limit)
        self.table(headers, rows, aligns, styles)

    def _located(self, entry: dict) -> None:
        rows, values = [], []
        for name, locs in entry["located"].items():
            vals = entry["config"].get(name)
            vals = vals if isinstance(vals, list) else [vals]
            for loc, v in zip(locs, vals):
                rows.append([name, f"{loc['offset']:#x}", loc.get("section") or "-", str(loc["size"]), "\0"])
                values.append(v)
        self._with_values(["name", "offset", "section", "size", "value"], rows, "lllrl",
                          [("yellow",), ("gray",), ("gray",), ("gray",), ()], values)

    def _legacy(self, entries: List[dict]) -> None:
        for e in entries:
            text = json.dumps(to_jsonable(e["config"]), indent=2, ensure_ascii=False)
            lines = text.splitlines()
            cap = None if self.full else 40
            for ln in lines[:cap]:
                self.line("    " + ln)
            if cap and len(lines) > cap:
                self.line("    " + self.st(f"{self.S['ell']} {len(lines) - cap} more lines (use --full or --json)", "dim"))

    def _kv(self, value: Any, indent: int) -> None:
        pad = " " * indent
        if isinstance(value, dict):
            w = max((len(str(k)) for k in value), default=0)
            for k, v in value.items():
                self.line(pad + self.st(str(k).ljust(w), "yellow") + "  "
                          + self.fmt_value(v, self.width - indent - w - 3))
        elif isinstance(value, list):
            for v in value:
                self.line(pad + self.S["dot"] + " " + self.fmt_value(v, self.width - indent - 3))
        else:
            self.line(pad + self.fmt_value(value, self.width - indent - 1))

    def _notes(self, res: dict, verbose: bool) -> None:
        groups: Dict[str, List[str]] = {}
        for w in res.get("warnings", []):
            if _NOTE in w and not verbose:
                continue
            w = w.replace(_NOTE + " ", "").replace(_NOTE, "")
            groups.setdefault(re.sub(r"0x[0-9a-fA-F]+", "0x#", w), []).append(w)
        warnings = [g[0] + (f"  (+{len(g) - 1} similar)" if len(g) > 1 else "") for g in groups.values()]
        errors = list(dict.fromkeys(res.get("errors", [])))
        if not (warnings or errors):
            return
        self.line()
        wrap = max(40, self.width - 8)
        for w in warnings:
            self._wrapped(self.st(self.S["warn"], "yellow"), w, wrap, "yellow")
        for e in errors:
            if e.startswith("hint:"):
                self._wrapped(self.st(self.S["arrow"], "cyan"), e[5:].strip(), wrap, "cyan")
            else:
                self._wrapped(self.st(self.S["bad"], "red"), e, wrap, "red")
        if verbose and res.get("traceback"):
            for ln in res["traceback"].rstrip().splitlines():
                self.line("    " + self.st(ln, "dim"))

    def _wrapped(self, mark: str, text: str, width: int, style: str) -> None:
        lines = textwrap.wrap(text, width) or [""]
        self.line(f"  {mark} " + self.st(lines[0], style))
        for ln in lines[1:]:
            self.line("    " + self.st(ln, style))

    # ---------------------------------------------------------------- summary
    def summary(self, results: List[dict], seconds: float, verbose: bool) -> None:
        ok = sum(r["status"] in ("success", "located") for r in results)
        nomatch = sum(r["status"] == "no_match" for r in results)
        failed = sum(r["status"] == "failed" for r in results)
        errors = sum(r["status"] == "error" for r in results)
        detected = sum(r["status"] == "detected" for r in results)

        def part(n, label, style):
            return self.st(f"{n} {label}", style if n else "gray")

        self.line(self.hr(0))
        bits = [self.st(f"{len(results)} scanned", "bold"), part(ok, "extracted", "green"),
                part(nomatch, "no match", "gray")]
        if detected:
            bits.append(part(detected, "detected only", "cyan"))
        bits += [part(failed, "failed", "yellow"), part(errors, "errors", "red")]
        self.line(("  " + self.st(self.S["dot"], "gray") + "  ").join(bits)
                  + "    " + self.st(f"{seconds:.2f} s", "dim"))
        if nomatch and not verbose:
            self.line(self.st("  use -v to list the files that did not match", "dim"))

    def saved(self, path, total: int, layout=()) -> None:
        self.line(self.st(f"  {self.S['arrow']} saved {total} file{'s' if total != 1 else ''} to {path}", "dim"))
        for line in layout:
            self.line(self.st("      " + line, "dim"))
