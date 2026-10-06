from __future__ import annotations

import os

import pefile

from ..resources import label
from .base import Image, Mapping

_MACHINES = {
    0x014C: "x86",
    0x8664: "x64",
    0x01C0: "arm",
    0x01C4: "arm",
    0xAA64: "arm64",
}

_SCN_EXEC = 0x20000000
_SCN_WRITE = 0x80000000


def load_pe(path) -> Image:
    """Parse a PE file (no import/resource parsing - we only need the layout)."""
    pe = pefile.PE(str(path), fast_load=True)
    base = pe.OPTIONAL_HEADER.ImageBase
    mappings = []

    headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    if headers:
        mappings.append(Mapping("headers", 0, headers, base, headers))

    for s in pe.sections:
        raw = s.SizeOfRawData
        virt = s.Misc_VirtualSize or raw
        name = s.Name.rstrip(b"\x00").decode("latin-1")
        mappings.append(
            Mapping(
                name=name,
                file_offset=s.PointerToRawData,
                file_size=raw,
                va=base + s.VirtualAddress,
                mem_size=virt,
                executable=bool(s.Characteristics & _SCN_EXEC),
                writable=bool(s.Characteristics & _SCN_WRITE),
            )
        )

    arch = _MACHINES.get(pe.FILE_HEADER.Machine)
    resources = _read_resources(pe)
    image = Image(
        format="pe",
        arch=arch,
        image_base=base,
        file_size=os.path.getsize(path),
        mappings=mappings,
        resources=resources,
    )
    image._closer = pe.close
    return image


def _str(obj):
    return None if obj is None else obj.decode("utf-8", "ignore") if hasattr(obj, "decode") else str(obj)


def _read_resources(pe, limit: int = 4000):
    """Flat list of the PE resources: type, name, language, file offset and size."""
    out = []
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        root = getattr(pe, "DIRECTORY_ENTRY_RESOURCE", None)
        for t in (root.entries if root else []):
            for n in getattr(getattr(t, "directory", None), "entries", []):
                for lang in getattr(getattr(n, "directory", None), "entries", []):
                    data = getattr(lang, "data", None)
                    if data is None:
                        continue
                    try:
                        offset = pe.get_offset_from_rva(data.struct.OffsetToData)
                    except Exception:
                        offset = None
                    rtype, rname = label(t.id, _str(t.name), n.id, _str(n.name))
                    out.append({"type_id": t.id, "type": rtype, "name_id": n.id, "name": rname,
                                "lang": lang.id, "offset": offset, "size": data.struct.Size})
                    if len(out) >= limit:
                        return out
    except Exception:
        pass
    return out
