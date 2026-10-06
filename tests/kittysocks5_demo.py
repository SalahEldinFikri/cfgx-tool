"""ARM32 ELF 'kittysocks5-like' sample built from the byte patterns in examples/kittysocks5/rule.yar."""
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from builders import build_elf32_arm  # noqa: E402

KEY = bytes.fromhex("5a1ec3077d9042b8e611c4f30a2977ad")
SIZES = [0x14A, 0x5DC, 8, 0xC, 3, 5, 0x11]
PLAINTEXTS = [
    bytes((j * 7 + 1) % 256 for j in range(SIZES[0])),       # binary blobs must survive too
    bytes((j * 13 + 5) % 256 for j in range(SIZES[1])),
    b"udp:8080", b"bot.example1", b"dns", b"admin", b"/bin/busybox ECCI",
]
BASE, TEXT_OFF, DATA_OFF = 0x10000, 0x100, 0x600


def xor(data, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def ldr_pc(rd, insn_va, pool_va):
    imm = pool_va - (insn_va + 8)
    assert 0 <= imm < 256, imm                       # the rule has `?? 10 9F E5` (imm hi nibble 0)
    return struct.pack("<I", 0xE59F0000 | rd << 12 | imm)


def build():
    # ---- data segment: key + encrypted entries
    data, addr = bytearray(), {}
    addr["key"] = len(data)
    data += KEY
    for i, pt in enumerate(PLAINTEXTS):
        while len(data) % 4:
            data.append(0)
        addr[i] = len(data)
        data += xor(pt, KEY)
    dva = lambda k: BASE + DATA_OFF + addr[k]

    # ---- code: key routine, then 7 x add_entry
    code = bytearray()
    va = lambda: BASE + TEXT_OFF + len(code)

    key_start = va()
    key_pool = key_start + 0x20
    code += ldr_pc(3, va(), key_pool)
    code += struct.pack("<8I", 0, 0, 0, 0, 0, 0, 0, 0)[:0]
    for word in (0xE7D33002, 0xE0203003, 0xE20330FF, 0xE5CC3000, 0xE51B3014, 0xE2833001, 0xE50B3014):
        code += struct.pack("<I", word)
    code += struct.pack("<I", dva("key"))                       # literal pool word -> table_key
    code += b"\x00\x00\xA0\xE1" * 4                               # nops between routines

    cfg_start = len(code)
    movs = [  # (R2 setup words, id of the next call)
        ([0xE3A02F52, 0xE2822002], 2), ([0xE3A02E5D, 0xE282200C], 3), ([0xE3A02008], 4),
        ([0xE3A0200C], 5), ([0xE3A02003], 6), ([0xE3A02005], 7), ([0xE3A02011], None),
    ]
    pool_pos = cfg_start + 7 * 5 * 4 + 4                         # pool right after the block
    ldr_slots = []
    code += struct.pack("<I", 0xE3A00001)                          # MOV R0,#1 (id of the first entry)
    for i, (setup, next_id) in enumerate(movs):
        ldr_slots.append(len(code))
        code += b"\x00\x00\x00\x00"                                # LDR R1,=entry (patched below)
        for w in setup:
            code += struct.pack("<I", w)
        code += bytes([0x10, 0x00, 0x00, 0xEB])                    # BL add_entry
        if next_id is not None:
            code += struct.pack("<I", 0xE3A00000 | next_id)        # MOV R0,#id
    code += struct.pack("<I", 0xE12FFF1E)                          # bx lr (end of block)
    pool_base = BASE + TEXT_OFF + len(code)
    for i in range(7):
        code += struct.pack("<I", dva(i))                          # literal pool words
    for i, slot in enumerate(ldr_slots):
        code[slot:slot + 4] = ldr_pc(1, BASE + TEXT_OFF + slot, pool_base + 4 * i)
    return build_elf32_arm(bytes(code), bytes(data))[0]


# =============================================================== ARM v2 ($config / $config2)
KEY2 = bytes.fromhex("c01d77a9035be4f2188ad6417c0b9e35")
V2_CONFIG = [bytes((j * 5 + 3) % 256 for j in range(125)), b"http://198.51.100.9/gate", b"port=8080"]
V2_CONFIG2 = [b"bot-id-001", b"admin"]


def build_v2():
    data, addr = bytearray(KEY2), {"key": 0}
    for tag, items in (("c", V2_CONFIG), ("d", V2_CONFIG2)):
        for i, pt in enumerate(items):
            while len(data) % 4:
                data.append(0)
            addr[(tag, i)] = len(data)
            data += xor(pt, KEY2)
    dva = lambda k: BASE + DATA_OFF + addr[k]
    code = bytearray()
    cur = lambda: BASE + TEXT_OFF + len(code)
    BL, NOP = bytes([0x10, 0x00, 0x00, 0xEB]), struct.pack("<I", 0xE1A00000)

    key_ldr = len(code)                                         # LDR R4,=table_key ; MOV R12,#0 ; ...
    code += b"\x00" * 4
    for w in (0xE3A0C000, 0xE1A03FCC, 0xE1A03E23, 0xE08C2003, 0xE59E0000, 0xE202200F, 0xE12FFF1E):
        code += struct.pack("<I", w)
    key_pool = cur()
    code += struct.pack("<I", dva("key"))
    code[key_ldr:key_ldr + 4] = ldr_pc(4, BASE + TEXT_OFF + key_ldr, key_pool)

    slots = []
    for i, pt in enumerate(V2_CONFIG):                          # LDR R1 ; MOV R2,#n ; BL
        slots.append((len(code), ("c", i)))
        code += b"\x00" * 4 + struct.pack("<I", 0xE3A02000 | len(pt)) + BL + NOP
    for i, pt in enumerate(V2_CONFIG2):                         # LDR R1 ; MOV R2,#n ; MOV R5,R0 ; BL
        slots.append((len(code), ("d", i)))
        code += b"\x00" * 4 + struct.pack("<I", 0xE3A02000 | len(pt)) + struct.pack("<I", 0xE1A05000) + BL + NOP
    pool = cur()
    for _, k in slots:
        code += struct.pack("<I", dva(k))
    for n, (slot, _) in enumerate(slots):
        code[slot:slot + 4] = ldr_pc(1, BASE + TEXT_OFF + slot, pool + 4 * n)
    return build_elf32_arm(bytes(code), bytes(data))[0]


# =============================================================== MIPS (PIC, big endian, GOT via $gp)
M_KEY = bytes.fromhex("0fe1d2c3b4a5968778695a4b3c2d1e0f")
M_SIZES = [59, 8, 12, 3, 5, 17]
M_PLAIN = [bytes((j * 11 + 7) % 256 for j in range(59)), b"udp:8080", b"bot.local-12", b"dns", b"admin",
           b"/bin/busybox ECCI"]
M_TEXT_VA, M_TEXT_OFF, M_TEXT_END, M_DATA_OFF, M_DATA_VA = 0x400000, 0x100, 0x600, 0x600, 0x410000
M_GP = M_DATA_VA + 0x7FF0                                       # GNU ld: _gp = start of .got + 0x7ff0


def build_mips(gp_via="phdr"):
    """gp_via: "phdr" (PT_MIPS_REGINFO) | "reginfo" (.reginfo section) | "got" (.got section only)
    | "none" (stripped: cfgx cannot know $gp)."""
    got_size = 0x20
    data = bytearray(got_size)
    key_off = len(data)
    data += M_KEY
    while len(data) % 4:
        data.append(0)
    page_off = len(data)                                         # the "page" the entries are addressed from
    offs = []
    for pt in M_PLAIN:
        offs.append(len(data) - page_off)
        data += xor(pt, M_KEY)
        while len(data) % 4:
            data.append(0)
    func_page = M_TEXT_VA + M_TEXT_OFF
    data[0:12] = struct.pack(">3I", M_DATA_VA + key_off, M_DATA_VA + page_off, func_page)   # GOT entries 0..2

    W = lambda w: struct.pack(">I", w)
    gp_off = lambda n: (4 * n - 0x7FF0) & 0xFFFF                 # imm of `lw rt, imm($gp)` for GOT entry n
    code = b"".join(W(w) for w in (
        0x8F820000 | gp_off(0), 0, 0x00431021, 0x90420000, 0, 0x00021600, 0x00021603, 0x8FC30010, 0,
        0x00621026, 0x00021600, 0x00021603, 0x8FC30010, 0, 0xA0620000, 0x8FC20010, 0, 0x24420001))
    for size, off in zip(M_SIZES, offs):
        code += W(0x8F820000 | gp_off(1)) + W(0)                 # lw $v0, page($gp) ; nop     (before the match)
        code += W(0x24450000 | off)                              # addiu $a1,$v0,off           (match starts here)
        code += W(0x24060000 | size)                             # li $a2,size
        code += W(0x8F820000 | gp_off(2)) + W(0)                 # lw $v0, func($gp) ; nop
        code += W(0x24590010) + W(0x0320F809) + W(0)             # addiu $t9,$v0,0x10 ; jalr $t9 ; delay slot

    blob = bytearray(M_DATA_OFF)
    blob[M_TEXT_OFF:M_TEXT_OFF + len(code)] = code
    blob += data
    blob += b"\x00" * ((-len(blob)) % 4)
    reg_off = len(blob)
    if gp_via in ("phdr", "reginfo"):
        blob += struct.pack(">6I", 0, 0, 0, 0, 0, M_GP)          # Elf32_RegInfo, ri_gp_value last

    shoff = shnum = shstrndx = 0
    if gp_via in ("reginfo", "got"):
        names = [b".text", b".got", b".data"] + ([b".reginfo"] if gp_via == "reginfo" else []) + [b".shstrtab"]
        strtab, name_at = b"\x00", {}
        for n in names:
            name_at[n] = len(strtab)
            strtab += n + b"\x00"
        str_off = len(blob)
        blob += strtab + b"\x00" * ((-len(strtab)) % 4)
        shoff = len(blob)
        sh = lambda n, t, f, a, o, sz: struct.pack(">10I", name_at[n], t, f, a, o, sz, 0, 0, 4, 0)
        secs = [b"\x00" * 40,
                sh(b".text", 1, 6, M_TEXT_VA + M_TEXT_OFF, M_TEXT_OFF, len(code)),
                sh(b".got", 1, 3, M_DATA_VA, M_DATA_OFF, got_size),
                sh(b".data", 1, 3, M_DATA_VA + got_size, M_DATA_OFF + got_size, len(data) - got_size)]
        if gp_via == "reginfo":
            secs.append(sh(b".reginfo", 0x70000006, 2, M_DATA_VA + (reg_off - M_DATA_OFF), reg_off, 24))
        secs.append(sh(b".shstrtab", 3, 0, 0, str_off, len(strtab)))
        shnum, shstrndx = len(secs), len(secs) - 1
        blob += b"".join(secs)

    phdrs = [struct.pack(">8I", 1, 0, M_TEXT_VA, M_TEXT_VA, M_TEXT_END, M_TEXT_END, 5, 0x1000),
             struct.pack(">8I", 1, M_DATA_OFF, M_DATA_VA, M_DATA_VA, len(data), len(data) + 0x100, 6, 0x1000)]
    if gp_via == "phdr":
        phdrs.append(struct.pack(">8I", 0x70000000, reg_off, M_DATA_VA + (reg_off - M_DATA_OFF),
                                 M_DATA_VA + (reg_off - M_DATA_OFF), 24, 24, 4, 4))
    ehdr = struct.pack(">16sHHIIIIIHHHHHH", b"\x7fELF\x01\x02\x01" + b"\x00" * 9, 2, 8, 1,
                       M_TEXT_VA + M_TEXT_OFF, 52, shoff, 0x70001005, 52, 32, len(phdrs), 40, shnum, shstrndx)
    blob[0:52 + 32 * len(phdrs)] = ehdr + b"".join(phdrs)
    return bytes(blob)


if __name__ == "__main__":
    out = Path(sys.argv[1] if len(sys.argv) > 1 else ".")
    out.mkdir(parents=True, exist_ok=True)
    (out / "kittysocks5_arm_v1.elf").write_bytes(build())
    (out / "kittysocks5_arm_v2.elf").write_bytes(build_v2())
    (out / "kittysocks5_mips.elf").write_bytes(build_mips())
    print("wrote 3 samples to", out)
