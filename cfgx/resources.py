"""PE resources addressed from rule meta:  ``<name>_resource = "TYPE/NAME[/LANG]"``.

TYPE  a standard name (RCDATA, RT_RCDATA, ICON, MANIFEST, VERSION, HTML ...), a number (10) or a custom type name ("BIN")
NAME  a number (101), a string name ("CONFIG"), ``*`` (all of that type) or ``#N`` (the N-th name of that type, from 0)
LANG  optional language id (1033, 0x409) or ``*`` (default: any)
"""
from __future__ import annotations

from typing import Dict, List

RESOURCE_TYPES = {
    "CURSOR": 1, "BITMAP": 2, "ICON": 3, "MENU": 4, "DIALOG": 5, "STRING": 6, "FONTDIR": 7, "FONT": 8,
    "ACCELERATOR": 9, "RCDATA": 10, "MESSAGETABLE": 11, "GROUP_CURSOR": 12, "GROUP_ICON": 14, "VERSION": 16,
    "DLGINCLUDE": 17, "PLUGPLAY": 19, "VXD": 20, "ANICURSOR": 21, "ANIICON": 22, "HTML": 23, "MANIFEST": 24,
}
_TYPE_NAME = {v: k for k, v in RESOURCE_TYPES.items()}


def _num(text: str):
    try:
        return int(text, 0)
    except ValueError:
        return None


def parse_spec(spec) -> tuple:
    parts = [p.strip() for p in str(spec).split("/")]
    if not 2 <= len(parts) <= 3 or not all(parts):
        raise ValueError(f"resource spec {spec!r} must look like TYPE/NAME or TYPE/NAME/LANG (e.g. RCDATA/101)")
    return parts[0], parts[1], parts[2] if len(parts) == 3 else "*"


def label(type_id, type_name, name_id, name) -> tuple:
    return (_TYPE_NAME.get(type_id, str(type_id)) if type_id is not None else type_name,
            str(name_id) if name_id is not None else name)


def select(resources: List[dict], spec) -> List[dict]:
    rtype, rname, rlang = parse_spec(spec)

    num = _num(rtype)
    if num is not None:
        pool = [r for r in resources if r["type_id"] == num]
    else:
        want = rtype.upper()
        want = want[3:] if want.startswith("RT_") else want
        pool = [r for r in resources if str(r["type"]).upper() == want]

    if rname == "*":
        pass
    elif rname.startswith("#"):
        order: List[str] = []
        for r in pool:
            if r["name"] not in order:
                order.append(r["name"])
        index = _num(rname[1:])
        if index is None:
            raise ValueError(f"bad resource name {rname!r}")
        pool = [r for r in pool if index < len(order) and r["name"] == order[index]]
    else:
        num = _num(rname)
        pool = [r for r in pool if (r["name_id"] == num if num is not None else str(r["name"]).upper() == rname.upper())]

    if rlang != "*":
        lang = _num(rlang)
        if lang is None:
            raise ValueError(f"bad resource language {rlang!r}")
        pool = [r for r in pool if r["lang"] == lang]
    return pool


def describe(resources: List[dict], limit: int = 12) -> str:
    seen: Dict[str, None] = {}
    for r in resources:
        seen[f"{r['type']}/{r['name']}"] = None
    items = list(seen)
    return ", ".join(items[:limit]) + (f", ... (+{len(items) - limit})" if len(items) > limit else "") or "none"
