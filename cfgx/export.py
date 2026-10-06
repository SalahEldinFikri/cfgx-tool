"""Write results to disk, organised per malware family.

    results/
      summary.json                       every sample of this run, with status, families and file
      Stealc/
        Stealc.family.json               the whole family: overview, keys seen, full result of every sample
        <sample>.cfgx.json               one file per sample
      _unmatched/
        <sample>.cfgx.json               samples no rule matched (or that could not be read)

A sample is filed under the first family its rules belong to.  The family file is *merged* with
what is already on disk (by sha256), so running cfgx on new samples later extends the same
family file instead of replacing it.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List

from . import __version__
from .output import decode_text, dumps, to_jsonable

UNMATCHED = "_unmatched"
_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


def safe_name(name, default: str = "unknown") -> str:
    """A family name that is safe as a Windows/Linux file or directory name."""
    cleaned = _BAD.sub("_", str(name)).strip(" .")
    return (cleaned or default)[:80]


def _keys(res: dict) -> List[dict]:
    found: Dict[tuple, dict] = {}
    for entry in res.get("config", []):
        for param, t in (entry.get("inputs") or {}).items():
            if param == "data" or not isinstance(t, dict) or "hex" not in t:
                continue
            value = t.get("value")
            if isinstance(value, (bytes, bytearray)):
                text = decode_text(bytes(value))
            else:
                text = value if isinstance(value, str) else None
            found[(param, t["hex"])] = {"param": param, "hex": t["hex"], "text": text}
    return list(found.values())


def overview(res: dict) -> dict:
    s = res.get("sample", {})
    return {
        "name": s.get("name"), "sha256": s.get("sha256"), "format": s.get("format"),
        "arch": s.get("arch"), "status": res.get("status"),
        "entries": len(res.get("config", [])), "rules": res.get("rules", []),
        "keys": _keys(res),
    }


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def _family_doc(family: str, results: List[dict], path: Path) -> dict:
    """Merge this run's results for ``family`` with an existing family file (same sha256 = replaced)."""
    mine = [to_jsonable(r) for r in results]
    new_hashes = {r["sample"].get("sha256") for r in mine}
    old = _read_json(path) if path.exists() else None
    kept = []
    if isinstance(old, dict):
        kept = [r for r in old.get("results", [])
                if isinstance(r, dict) and r.get("sample", {}).get("sha256") not in new_hashes]
    merged = sorted(kept + mine, key=lambda r: (r.get("sample", {}).get("name") or ""))
    samples = [overview(r) for r in merged]

    key_count: Dict[tuple, dict] = {}
    for o in samples:
        for k in o["keys"]:
            slot = key_count.setdefault((k["param"], k["hex"]), {**k, "samples": 0})
            slot["samples"] += 1
    return {
        "schema": "cfgx-family/1",
        "family": family,
        "tool": f"cfgx {__version__}",
        "updated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "samples": samples,
        "keys": list(key_count.values()),
        "results": merged,
    }


def save_directory(results: List[dict], out: Path) -> dict:
    """Write everything under ``out``; returns {"total": n_files, "layout": [console lines]}."""
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    total = 0
    per_dir: Dict[str, int] = {}
    taken: Dict[str, set] = {}
    where: List[str] = []

    for res in results:
        fams = res.get("families") or []
        dname = safe_name(fams[0]) if fams else UNMATCHED
        d = out / dname
        d.mkdir(exist_ok=True)
        fname = f"{res['sample']['name']}.cfgx.json"
        if fname in taken.setdefault(dname, set()):         # same file name from another folder
            fname = f"{(res['sample'].get('sha256') or 'dup')[:8]}_{fname}"
        taken[dname].add(fname)
        (d / fname).write_text(dumps(res), encoding="utf-8")
        where.append(f"{dname}/{fname}")
        per_dir[dname] = per_dir.get(dname, 0) + 1
        total += 1

    families: List[str] = []
    for res in results:
        for f in res.get("families") or []:
            if f not in families:
                families.append(f)

    family_files: Dict[str, str] = {}
    for fam in families:
        dname = safe_name(fam)
        d = out / dname
        d.mkdir(exist_ok=True)
        path = d / f"{dname}.family.json"
        members = [r for r in results if fam in (r.get("families") or [])]
        doc = _family_doc(fam, members, path)
        path.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
        family_files[dname] = path.name
        per_dir.setdefault(dname, 0)
        total += 1

    summary = [{
        "sample": r["sample"].get("path"), "name": r["sample"].get("name"),
        "sha256": r["sample"].get("sha256"), "status": r["status"],
        "families": r.get("families", []), "rules": r.get("rules", []), "file": w,
    } for r, w in zip(results, where)]
    (out / "summary.json").write_text(dumps(summary), encoding="utf-8")
    total += 1

    layout = []
    for dname in sorted(per_dir):
        n = per_dir[dname]
        line = f"{dname}{os.sep}  {n} sample{'s' if n != 1 else ''}"
        if dname in family_files:
            line += f" + {family_files[dname]}"
        layout.append(line)
    layout.append("summary.json")
    return {"total": total, "layout": layout}
