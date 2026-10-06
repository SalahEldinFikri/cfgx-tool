from __future__ import annotations

import os

from elftools.elf.elffile import ELFFile

from .base import Image, Mapping

_MACHINES = {
    "EM_386": "x86",
    "EM_X86_64": "x64",
    "EM_ARM": "arm",
    "EM_AARCH64": "arm64",
    "EM_MIPS": "mips",
}

_PT_LOAD = "PT_LOAD"


def _mips_gp(elf, fh):
    """Best-effort $gp of a MIPS ELF: .reginfo, PT_MIPS_REGINFO, then .got/DT_PLTGOT + 0x7ff0
    (GNU ld's _gp convention).  Returns (value, source) or (None, None)."""
    order = "little" if elf.little_endian else "big"
    try:
        sec = elf.get_section_by_name(".reginfo")
        if sec is not None:
            data = sec.data()
            if len(data) >= 24 and int.from_bytes(data[20:24], order):
                return int.from_bytes(data[20:24], order), ".reginfo"
        for seg in elf.iter_segments():
            if seg["p_type"] in ("PT_MIPS_REGINFO", 0x70000000):
                fh.seek(seg["p_offset"])
                data = fh.read(24)
                if len(data) == 24 and int.from_bytes(data[20:24], order):
                    return int.from_bytes(data[20:24], order), "PT_MIPS_REGINFO"
        sec = elf.get_section_by_name(".got")
        if sec is not None and sec["sh_addr"]:
            return sec["sh_addr"] + 0x7FF0, ".got + 0x7ff0"
        dyn = elf.get_section_by_name(".dynamic")
        if dyn is not None:
            for tag in dyn.iter_tags():
                if tag.entry.d_tag == "DT_PLTGOT":
                    return tag.entry.d_val + 0x7FF0, "DT_PLTGOT + 0x7ff0"
    except Exception:
        pass
    return None, None


def load_elf(path) -> Image:
    """Parse an ELF file using its section table for names and its PT_LOAD
    segments for virtual-address mapping (what the loader actually uses)."""
    fh = open(path, "rb")
    try:
        elf = ELFFile(fh)
        mappings = []

        for s in elf.iter_sections():
            if not (s["sh_flags"] & 0x2):                      # not SHF_ALLOC
                continue
            nobits = s["sh_type"] == "SHT_NOBITS"              # .bss: in memory, no bytes in the file
            if nobits and (s["sh_flags"] & 0x400):             # .tbss overlaps the next sections: skip it
                continue
            mappings.append(
                Mapping(
                    name=s.name,
                    file_offset=s["sh_offset"],
                    file_size=0 if nobits else s["sh_size"],
                    va=s["sh_addr"],
                    mem_size=s["sh_size"],
                    executable=bool(s["sh_flags"] & 0x4),      # SHF_EXECINSTR
                    writable=bool(s["sh_flags"] & 0x1),        # SHF_WRITE
                )
            )

        # Stripped/section-less binaries: fall back to program headers.
        if not mappings:
            for i, seg in enumerate(elf.iter_segments()):
                if seg["p_type"] != _PT_LOAD:
                    continue
                mappings.append(
                    Mapping(
                        name=f"LOAD{i}",
                        file_offset=seg["p_offset"],
                        file_size=seg["p_filesz"],
                        va=seg["p_vaddr"],
                        mem_size=seg["p_memsz"],
                        executable=bool(seg["p_flags"] & 0x1),
                        writable=bool(seg["p_flags"] & 0x2),
                    )
                )

        loads = [s["p_vaddr"] for s in elf.iter_segments() if s["p_type"] == _PT_LOAD]
        image_base = min(loads) if loads else 0
        arch = _MACHINES.get(elf["e_machine"])
        if arch == "mips" and elf.elfclass == 64:
            arch = "mips64"
        image = Image(
            format="elf",
            arch=arch,
            image_base=image_base,
            file_size=os.path.getsize(path),
            mappings=mappings,
            endian="little" if elf.little_endian else "big",
        )
        if arch == "mips":
            image.gp, image.gp_source = _mips_gp(elf, fh)
    except Exception:
        fh.close()
        raise
    image._closer = fh.close
    return image
