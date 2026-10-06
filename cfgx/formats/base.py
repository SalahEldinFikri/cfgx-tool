"""Format-independent view of an executable image.

Every supported container (PE, ELF, raw blob) is reduced to the same small
interface so the rest of cfgx never has to care which one it is dealing with.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class Mapping:
    """One contiguous file range that is mapped into memory."""

    name: str
    file_offset: int
    file_size: int      # bytes actually present in the file
    va: int
    mem_size: int       # bytes occupied in memory (>= file_size for .bss-like tails)
    executable: bool = False
    writable: bool = False

    def contains_offset(self, offset: int) -> bool:
        return self.file_offset <= offset < self.file_offset + self.file_size

    def contains_va(self, va: int) -> bool:
        return self.va <= va < self.va + max(self.mem_size, self.file_size)


@dataclass
class Image:
    format: str                 # "pe" | "elf" | "raw"
    arch: Optional[str]         # "x86" | "x64" | "arm" | "arm64" | None
    image_base: int
    file_size: int
    mappings: List[Mapping] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)   # loader remarks shown to the user
    resources: List[dict] = field(default_factory=list)   # PE resources: type, name, lang, offset, size
    gp: Optional[int] = None           # MIPS: value of $gp (start of the GOT + 0x7ff0)
    gp_source: Optional[str] = None    # where gp came from (.reginfo, .got ...)
    endian: str = "little"          # byte order of the code/data (ELF e_ident, PE is always little)
    _closer: object = None

    # ---- address translation -------------------------------------------------
    def mapping_at_offset(self, offset: int) -> Optional[Mapping]:
        for m in self.mappings:
            if m.contains_offset(offset):
                return m
        return None

    def mapping_at_va(self, va: int) -> Optional[Mapping]:
        for m in self.mappings:
            if m.contains_va(va):
                return m
        return None

    def offset_to_va(self, offset: int) -> Optional[int]:
        m = self.mapping_at_offset(offset)
        return None if m is None else m.va + (offset - m.file_offset)

    def va_to_offset(self, va: int) -> Optional[int]:
        """File offset for a virtual address, or None.

        Returns None for addresses that are mapped in memory but have no bytes
        in the file (the uninitialised tail of a section, .bss, ...).
        """
        m = self.mapping_at_va(va)
        if m is None:
            return None
        delta = va - m.va
        if delta >= m.file_size:
            return None
        return m.file_offset + delta

    def offset_to_rva(self, offset: int) -> Optional[int]:
        va = self.offset_to_va(offset)
        return None if va is None else va - self.image_base

    def rva_to_offset(self, rva: int) -> Optional[int]:
        return self.va_to_offset(rva + self.image_base)

    def section_name(self, offset: int) -> Optional[str]:
        m = self.mapping_at_offset(offset)
        return None if m is None else m.name

    def is_executable(self, offset: int) -> bool:
        m = self.mapping_at_offset(offset)
        return bool(m and m.executable)

    @property
    def bits(self) -> Optional[int]:
        return {"x86": 32, "arm": 32, "mips": 32, "x64": 64, "arm64": 64, "mips64": 64}.get(self.arch)

    def describe(self) -> dict:
        return {
            "format": self.format,
            "arch": self.arch,
            "image_base": self.image_base,
            "endian": self.endian,
        }

    def close(self) -> None:
        if self._closer is not None:
            self._closer()
            self._closer = None
