"""Executable format support.

``load_image`` sniffs the file and returns a format-independent ``Image``.
Anything that is not a valid PE or ELF is loaded as a flat ``raw`` blob, so
memory dumps and unpacked payloads work too.
"""
from __future__ import annotations

import struct
from pathlib import Path

from .base import Image, Mapping
from .elf import load_elf
from .pe import load_pe
from .raw import load_raw

__all__ = ["Image", "Mapping", "detect_format", "load_image"]


def detect_format(path) -> str:
    """Return "pe", "elf" or "raw" based on file headers (not on extension)."""
    with open(path, "rb") as f:
        head = f.read(0x40)
        if head.startswith(b"\x7fELF"):
            return "elf"
        if head.startswith(b"MZ") and len(head) >= 0x40:
            (e_lfanew,) = struct.unpack_from("<I", head, 0x3C)
            f.seek(e_lfanew)
            if f.read(4) == b"PE\x00\x00":
                return "pe"
    return "raw"


def _short(e: Exception) -> str:
    text = f"{type(e).__name__}: {e}"
    return text if len(text) <= 110 else text[:107] + "..."


def load_image(path, force_format=None, arch=None) -> Image:
    path = Path(path)
    fmt = force_format or detect_format(path)
    note = None
    if fmt in ("pe", "elf"):
        try:
            return load_pe(path) if fmt == "pe" else load_elf(path)
        except Exception as e:
            if force_format:
                raise
            note = (f"{fmt.upper()} headers found but they could not be parsed ({_short(e)}); "
                    f"scanned as a raw blob, so code references cannot be resolved")
            fmt = "raw"
    elif not force_format:
        with open(path, "rb") as f:
            if f.read(2) == b"MZ":
                note = ("starts with 'MZ' but has no valid PE signature; scanned as a raw blob, "
                        "so code references cannot be resolved")
    image = load_raw(path, arch=arch)
    if note:
        image.notes.append(note)
    return image
