"""Tiny PE / ELF writers so tests need no binary fixtures."""
import struct

# ---------------------------------------------------------------- PE ------
def build_rsrc(resources, rva):
    """resources: [(type, name, lang, data)], type/name: int or str. Returns the resource directory + data."""
    tree = {}
    for t, n, l, d in resources:
        tree.setdefault(t, {}).setdefault(n, {})[l] = d
    order = lambda keys: sorted([k for k in keys if isinstance(k, str)], key=str.upper) + sorted(
        k for k in keys if isinstance(k, int))
    names = []
    for t, ns in tree.items():
        for k in [t, *ns]:
            if isinstance(k, str) and k not in names:
                names.append(k)

    def dsize(d):                                      # a directory: header + entries + children
        return 16 + 8 * len(d) + sum(dsize(c) if isinstance(c, dict) else 16 for c in d.values())

    struct_size = dsize(tree)
    str_off, off = {}, struct_size
    for k in names:
        str_off[k] = off
        off += 2 + 2 * len(k)
        off += off % 2
    blob_off, blobs = {}, bytearray()
    off += (-off) % 4
    data_start = off
    leaves = [(t, n, l, d) for t, n, l, d in resources]
    for t, n, l, d in leaves:
        blob_off[(t, n, l)] = data_start + len(blobs)
        blobs += d + b"\x00" * ((-len(d)) % 4)
    out = bytearray(data_start + len(blobs))

    def write(d, at, path):
        keys = order(d)
        named = sum(isinstance(k, str) for k in keys)
        struct.pack_into("<IIHHHH", out, at, 0, 0, 0, 0, named, len(keys) - named)
        child = at + 16 + 8 * len(keys)
        for i, k in enumerate(keys):
            ident = (0x80000000 | str_off[k]) if isinstance(k, str) else k
            c = d[k]
            if isinstance(c, dict):
                struct.pack_into("<II", out, at + 16 + 8 * i, ident, 0x80000000 | child)
                write(c, child, path + (k,))
                child += dsize(c)
            else:
                struct.pack_into("<II", out, at + 16 + 8 * i, ident, child)
                full = path + (k,)
                struct.pack_into("<IIII", out, child, rva + blob_off[full], len(c), 0, 0)
                child += 16

    write(tree, 0, ())
    for k, o in str_off.items():
        struct.pack_into("<H", out, o, len(k))
        out[o + 2:o + 2 + 2 * len(k)] = k.encode("utf-16le")
    out[data_start:] = blobs
    return bytes(out)


def build_pe(text: bytes, rdata: bytes, bits=64, bss_size=0x1000, image_base=None, resources=None):
    """3 sections: .text (VA 0x1000, X), .rdata (VA 0x2000, R), .bss (VA 0x3000, no file data).

    Returns (file_bytes, layout) where layout holds the section VAs.
    """
    is64 = bits == 64
    base = image_base or (0x140000000 if is64 else 0x400000)
    file_align, sect_align = 0x200, 0x1000
    opt_size = 0xF0 if is64 else 0xE0
    n_sections = 4 if resources else 3
    headers_size = 0x200

    text_raw = (len(text) + file_align - 1) // file_align * file_align or file_align
    rdata_raw = (len(rdata) + file_align - 1) // file_align * file_align or file_align
    text_off, rdata_off = headers_size, headers_size + text_raw

    dos = bytearray(0x40)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)

    coff = struct.pack(
        "<HHIIIHH",
        0x8664 if is64 else 0x014C, n_sections, 0, 0, 0, opt_size,
        0x0022 if is64 else 0x0102,
    )

    align = lambda n: (n + 0xFFF) & ~0xFFF
    rdata_rva = max(0x2000, 0x1000 + align(len(text)))
    bss_rva = max(0x3000, rdata_rva + align(len(rdata)))
    size_of_image = bss_rva + align(bss_size)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, 0x20B if is64 else 0x10B)
    struct.pack_into("<I", opt, 4, text_raw)
    struct.pack_into("<I", opt, 16, 0x1000)               # entry point
    struct.pack_into("<I", opt, 20, 0x1000)               # base of code
    if is64:
        struct.pack_into("<Q", opt, 24, base)
        off = 32
    else:
        struct.pack_into("<I", opt, 28, base)
        off = 32
    struct.pack_into("<II", opt, off, sect_align, file_align)
    struct.pack_into("<HHHHHH", opt, 40, 6, 0, 0, 0, 6, 0)
    struct.pack_into("<I", opt, 56, size_of_image)
    struct.pack_into("<I", opt, 60, headers_size)
    struct.pack_into("<H", opt, 68, 3)                    # subsystem console
    if is64:
        struct.pack_into("<I", opt, 108, 16)
    else:
        struct.pack_into("<I", opt, 92, 16)

    def sect(name, vsize, va, rsize, roff, flags):
        return struct.pack("<8sIIIIIIHHI", name, vsize, va, rsize, roff, 0, 0, 0, 0, flags)

    sections = (
        sect(b".text", len(text), 0x1000, text_raw, text_off, 0x60000020)
        + sect(b".rdata", len(rdata), rdata_rva, rdata_raw, rdata_off, 0x40000040)
        + sect(b".bss", bss_size, bss_rva, 0, 0, 0xC0000080)
    )
    rsrc = b""
    if resources:                                      # .rsrc after .bss, DataDirectory[2] points at it
        rsrc_rva = bss_rva + align(bss_size)
        rsrc = build_rsrc(resources, rsrc_rva)
        rsrc_raw = (len(rsrc) + file_align - 1) // file_align * file_align
        sections += sect(b".rsrc", len(rsrc), rsrc_rva, rsrc_raw, rdata_off + rdata_raw, 0x40000040)
        size_of_image = rsrc_rva + align(len(rsrc))
        struct.pack_into("<I", opt, 56, size_of_image)
        struct.pack_into("<II", opt, (112 if is64 else 96) + 16, rsrc_rva, len(rsrc))
    header = bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sections
    header = header.ljust(headers_size, b"\x00")
    header = (bytes(dos) + b"PE\x00\x00" + coff + bytes(opt) + sections).ljust(headers_size, b"\x00")
    blob = header + text.ljust(text_raw, b"\x00") + rdata.ljust(rdata_raw, b"\x00")
    if resources:
        blob += rsrc.ljust((len(rsrc) + file_align - 1) // file_align * file_align, b"\x00")
    layout = {
        "base": base,
        "text_va": base + 0x1000, "text_off": text_off,
        "rdata_va": base + rdata_rva, "rdata_off": rdata_off,
        "bss_va": base + bss_rva,
    }
    return blob, layout


# ---------------------------------------------------------------- ELF -----
def build_elf64(text: bytes, data: bytes, bss=0x100):
    """No section headers (stripped style). Two PT_LOAD segments:
    LOAD0 R+X: file 0..0x200, VA 0x400000..;  LOAD1 RW: file 0x200.., VA 0x400200.."""
    base = 0x400000
    ehsize, phsize = 64, 56
    code_off = 0x100
    data_off = 0x200
    assert len(text) <= data_off - code_off
    ehdr = struct.pack(
        "<16sHHIQQQIHHHHHH",
        b"\x7fELF\x02\x01\x01" + b"\x00" * 9,
        2, 62, 1, base + code_off, ehsize, 0, 0, ehsize, phsize, 2, 64, 0, 0,
    )
    ph0 = struct.pack("<IIQQQQQQ", 1, 5, 0, base, base, data_off, data_off, 0x1000)
    ph1 = struct.pack("<IIQQQQQQ", 1, 6, data_off, base + data_off, base + data_off,
                      len(data), len(data) + bss, 0x1000)
    blob = (ehdr + ph0 + ph1).ljust(code_off, b"\x00")
    blob += text.ljust(data_off - code_off, b"\x00") + data
    return blob, {"base": base, "text_va": base + code_off, "text_off": code_off,
                  "data_va": base + data_off, "data_off": data_off}


def rip_disp(instr_va, length, target_va):
    """disp32 for a RIP-relative instruction."""
    return struct.pack("<i", target_va - (instr_va + length))


def build_elf32(text: bytes, data: bytes, machine: int, big_endian: bool = False,
                text_va: int = 0x10000, data_va=None, bss=0x100, text_end=0x600, sections=False):
    """Stripped 32-bit ELF, two PT_LOAD segments.
    LOAD0 R+X: file 0..text_end at ``text_va`` (code starts at file offset 0x100);
    LOAD1 RW : file text_end.. at ``data_va`` (default text_va + text_end)."""
    e = ">" if big_endian else "<"
    code_off = 0x100
    assert len(text) <= text_end - code_off
    data_va = text_va + text_end if data_va is None else data_va
    ph0 = struct.pack(e + "IIIIIIII", 1, 0, text_va, text_va, text_end, text_end, 5, 0x1000)
    ph1 = struct.pack(e + "IIIIIIII", 1, text_end, data_va, data_va, len(data), len(data) + bss, 6, 0x1000)
    blob = bytearray((b"\x00" * 52 + ph0 + ph1).ljust(code_off, b"\x00"))
    blob += text.ljust(text_end - code_off, b"\x00") + data
    shoff = shnum = shstrndx = 0
    if sections:                                   # a real section table, with .bss as NOBITS (as in real binaries)
        names = [b".text", b".data", b".bss", b".shstrtab"]
        strtab, at = b"\x00", {}
        for n in names:
            at[n] = len(strtab)
            strtab += n + b"\x00"
        str_off = len(blob)
        blob += strtab + b"\x00" * ((-len(strtab)) % 4)
        shoff = len(blob)
        sh = lambda n, t, f, a, o, sz: struct.pack(e + "10I", at[n], t, f, a, o, sz, 0, 0, 4, 0)
        table = [b"\x00" * 40,
                 sh(b".text", 1, 6, text_va + code_off, code_off, len(text)),
                 sh(b".data", 1, 3, data_va, text_end, len(data)),
                 sh(b".bss", 8, 3, data_va + len(data), text_end + len(data), bss),
                 sh(b".shstrtab", 3, 0, 0, str_off, len(strtab))]
        shnum, shstrndx = len(table), len(table) - 1
        blob += b"".join(table)
    blob[0:52] = struct.pack(
        e + "16sHHIIIIIHHHHHH",
        b"\x7fELF\x01" + (b"\x02" if big_endian else b"\x01") + b"\x01" + b"\x00" * 9,
        2, machine, 1, text_va + code_off, 52, shoff, 0, 52, 32, 2, 40, shnum, shstrndx,
    )
    blob = bytes(blob)
    return blob, {"text_va": text_va + code_off, "data_va": data_va}


def build_elf32_arm(text: bytes, data: bytes, bss=0x100, text_end=0x600):
    blob, info = build_elf32(text, data, machine=40, text_va=0x10000, bss=bss, text_end=text_end)
    info["base"] = 0x10000
    return blob, info
