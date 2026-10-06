"""Read-only, memory-mapped access to the sample.

Plugins (and the engine) read bytes through a ``Reader`` so nobody has to open
files, seek, or translate addresses by hand.
"""
from __future__ import annotations

import mmap
import os
import struct
from typing import Iterator, Optional

from .formats.base import Image


class Reader:
    def __init__(self, path, image: Optional[Image] = None):
        self.path = str(path)
        self.image = image
        self.size = os.path.getsize(self.path)
        self._fh = open(self.path, "rb")
        self._mm = None
        if self.size:
            try:
                self._mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
            except (OSError, ValueError):          # e.g. some Windows/AV/network setups
                self._mm = self._fh.read()         # plain bytes supports the same slicing/find

    # ---- lifecycle -----------------------------------------------------------
    def close(self) -> None:
        if self._mm is not None:
            if hasattr(self._mm, "close"):
                self._mm.close()
            self._mm = None
        if self._fh is not None:
            self._fh.close()
            self._fh = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __len__(self) -> int:
        return self.size

    # ---- raw access ----------------------------------------------------------
    def read(self, offset: int, size: int) -> bytes:
        """Read up to ``size`` bytes at file ``offset`` (shorter at end of file)."""
        if not isinstance(offset, int) or not isinstance(size, int):
            raise TypeError("offset and size must be integers")
        if offset < 0 or size < 0:
            raise ValueError("offset and size cannot be negative")
        if self._mm is None:
            return b""
        return self._mm[offset:offset + size]

    def __getitem__(self, item):
        if isinstance(item, slice):
            start = item.start or 0
            stop = self.size if item.stop is None else item.stop
            return self.read(start, max(0, stop - start))
        return self.read(item, 1)[0]

    def read_until(self, offset: int, terminator: bytes = b"\x00", max_size: int = 65536) -> bytes:
        """Bytes from ``offset`` up to (not including) ``terminator``."""
        chunk = self.read(offset, max_size)
        end = chunk.find(terminator)
        return chunk if end == -1 else chunk[:end]

    def read_cstring(self, offset: int, max_size: int = 4096) -> bytes:
        return self.read_until(offset, b"\x00", max_size)

    def read_wstring(self, offset: int, max_chars: int = 2048) -> bytes:
        """UTF-16LE NUL-terminated string, returned as raw bytes (no terminator)."""
        chunk = self.read(offset, max_chars * 2)
        for i in range(0, len(chunk) - 1, 2):
            if chunk[i] == 0 and chunk[i + 1] == 0:
                return chunk[:i]
        return chunk

    def unpack(self, fmt: str, offset: int):
        """``struct.unpack`` at an offset; ``fmt`` is little-endian unless prefixed."""
        if fmt[0] not in "<>=!@":
            fmt = "<" + fmt
        size = struct.calcsize(fmt)
        data = self.read(offset, size)
        if len(data) != size:
            raise ValueError(f"cannot read {size} bytes at offset {offset:#x}")
        return struct.unpack(fmt, data)

    def u8(self, offset):  return self.unpack("B", offset)[0]
    def u16(self, offset): return self.unpack("H", offset)[0]
    def u32(self, offset): return self.unpack("I", offset)[0]
    def u64(self, offset): return self.unpack("Q", offset)[0]
    def i32(self, offset): return self.unpack("i", offset)[0]

    # ---- searching -------------------------------------------------------------
    def find(self, pattern: bytes, start: int = 0, end: Optional[int] = None) -> int:
        if self._mm is None:
            return -1
        return self._mm.find(pattern, start, self.size if end is None else end)

    def find_all(self, pattern: bytes) -> Iterator[int]:
        pos = self.find(pattern)
        while pos != -1:
            yield pos
            pos = self.find(pattern, pos + 1)

    # ---- address translation -------------------------------------------------------
    def _need_image(self) -> Image:
        if self.image is None:
            raise ValueError("address translation is not available")
        return self.image

    def rva_to_offset(self, rva: int) -> Optional[int]:
        if rva < 0:
            raise ValueError("RVA cannot be negative")
        return self._need_image().rva_to_offset(rva)

    def va_to_offset(self, va: int) -> Optional[int]:
        if va < 0:
            raise ValueError("VA cannot be negative")
        return self._need_image().va_to_offset(va)

    def offset_to_va(self, offset: int) -> Optional[int]:
        return self._need_image().offset_to_va(offset)

    def read_va(self, va: int, size: int) -> bytes:
        offset = self.va_to_offset(va)
        if offset is None:
            raise ValueError(f"VA {va:#x} is not backed by file data")
        return self.read(offset, size)

    def section(self, name: str) -> bytes:
        """Raw file bytes of a named section (``.rdata``, ``.data`` ...)."""
        for m in self._need_image().mappings:
            if m.name == name:
                return self.read(m.file_offset, m.file_size)
        raise KeyError(f"no section named {name!r}")

    @property
    def sections(self):
        return [m.name for m in self._need_image().mappings]


# Backwards-compatible name used by older plugins and the old README.
SampleReader = Reader
