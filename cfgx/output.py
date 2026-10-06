"""JSON-safe serialisation and plaintext auto-parsing."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    ok = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return ok / len(text)


def _looks_utf16le(b: bytes) -> bool:
    if len(b) < 4:
        return False
    if len(b) % 2:
        b = b + b"\x00"
    return b[1::2].count(0) >= 0.8 * (len(b) // 2)


def decode_text(b: bytes, min_ratio: float = 0.95):
    """Best-effort text decode (UTF-16LE or UTF-8). Returns ``str`` or ``None``
    when the data is binary."""
    if not b.strip(b"\x00"):
        return None
    candidates = []
    if _looks_utf16le(b):
        candidates.append(("utf-16-le", b if len(b) % 2 == 0 else b + b"\x00"))
    candidates.append(("utf-8", b))
    for enc, raw in candidates:
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        text = text.rstrip("\x00")
        if text and printable_ratio(text) >= min_ratio:
            return text
    return None


def auto_parse(value: Any) -> Any:
    """Turn decrypted bytes into the most useful structure:
    JSON -> object, text -> str, anything else stays bytes."""
    if isinstance(value, (bytes, bytearray)):
        text = decode_text(bytes(value))
        if text is None:
            return bytes(value)
        value = text
    if isinstance(value, str):
        s = value.strip()
        if s[:1] in "{[":
            try:
                return json.loads(s)
            except ValueError:
                pass
        return value
    return value


def score_plaintext(b: bytes) -> float:
    """0..1 plausibility of a decryption result (used only to choose between
    several key/data candidates)."""
    if not b:
        return 0.0
    text = decode_text(b, 0.0)
    if text is None:
        ascii_part = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
        return ascii_part / len(b) * 0.5
    ratio = printable_ratio(text)
    return min(1.0, ratio + (0.05 if auto_parse(text) is not text else 0.0))


def to_jsonable(obj: Any) -> Any:
    """Recursively convert to something ``json.dumps`` accepts, without losing
    binary data: printable bytes become text, other bytes become {"hex": ...}."""
    if obj is None or isinstance(obj, (bool, int, float, str)):
        return obj
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        text = decode_text(b)
        return text if text is not None else {"hex": b.hex()}
    if dataclasses.is_dataclass(obj) and not isinstance(obj, type):
        return to_jsonable(dataclasses.asdict(obj))
    if isinstance(obj, dict):
        return {str(k): to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set, frozenset)):
        return [to_jsonable(v) for v in obj]
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def dumps(obj: Any, indent: int = 2) -> str:
    return json.dumps(to_jsonable(obj), indent=indent, ensure_ascii=False)
