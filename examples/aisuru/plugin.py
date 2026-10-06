"""AISURU / AIRASHI: plain RC4 (x86 v1, ARM) and the custom cipher of the x86 v2 string table.

The algorithm is chosen by the rule's meta (``algo``), so one plugin serves every rule:

  algo = "rc4"         plain RC4, fresh key schedule per entry (confirmed on a real x86 v1 sample)
  algo = "aisuru_v2"   x86 v2: key schedule = sub_804D070 (S[i] = 13 - 89*i, a key-dependent pass over four big-endian
                       key words, then five LCG-driven scrambling passes) + the PRGA of routine three (RC4 + running sum
                       + a 32-bit LFSR + nibble/rotate output mix).  VERIFIED against the keystream recovered from
                       real samples (first 24 bytes: 7ded2d4c0dba1a7c16d82a4e9c2061c12e01dbf9a7a3ace3).
  algo = "auto"        try every algorithm on every entry and keep the one that gives readable text (-v shows which)

Entries of the v2 table carry a flag byte; unencrypted ones (e.g. "\r\n") are returned as they are.
"""
from cfgx.crypto import rc4, text_score

FAMILY = "AISURU"
M32 = 0xFFFFFFFF


def ksa_v2(key):
    """sub_804D070(ctx, key, len): returns the 256-byte S-box (ctx[0..255])."""
    n = len(key)
    kb = [key[i % n] for i in range(16)]                               # key repeated/truncated to 16 bytes
    w = [int.from_bytes(bytes(kb[i:i + 4]), "big") for i in (0, 4, 8, 12)]   # _byteswap_ulong of each LE dword
    s = [(13 - 89 * i) & 0xFF for i in range(256)]                     # LOBYTE(v6)=13; v6 -= 89
    j = 0
    for i in range(256):
        v = s[i]
        j = ((w[i % 4] >> (i % 32)) + v + j) & 0xFF
        s[i] = s[j]
        s[j] = v
    seed = (-526070826) & M32
    for jj in range(5):
        for k in range(256):
            seed = (1103515245 * seed + 12345) & M32
            v12 = (j + (((seed * s[k]) & M32) >> 24)) & 0xFF
            v13 = (seed ^ w[(k + jj) % 4] ^ s[k]) & 0xFF
            j = (v13 + v12) & 0xFF
            s[k] = s[j]
            s[j] = v13
    return s


def v2_crypt(data, key):
    """Routine three on top of ksa_v2. Symmetric (XOR with a keystream), so it encrypts and decrypts."""
    s, out = ksa_v2(key), bytearray(data)
    i = j = k = 0                       # v4, v5, v13
    lfsr = 1                            # v12
    for n in range(len(out)):
        i = (i + 1) & 0xFF
        si = s[i]
        j = (j + si) & 0xFF
        k = (k + s[(i + j) & 0xFF]) & 0xFF            # read before the swap
        s[i], s[j] = s[j], si
        lfsr = ((lfsr << 1) | (lfsr >> 31)) & M32      # __ROR4__(v12, 31) == rotate left by 1
        if lfsr & 1:
            lfsr ^= 0xD800A4
        z = s[(s[(i + j) & 0xFF] + s[(j + k) & 0xFF]) & 0xFF]
        b = (lfsr ^ z) & 0xFF
        out[n] ^= (b >> 4) ^ (((b << 3) | (b >> 5)) & 0xFF)  # (b >> 4) ^ __ROL1__(b, 3)
    return bytes(out)


def _already_text(data):
    """Unencrypted table entries (flag byte 0): CRLF-like separators or clearly readable text."""
    return bool(data) and (set(data) <= set(b"\r\n\t ") or (len(data) >= 4 and text_score(data) >= 0.97))


def _v2(data, key):
    return data if _already_text(data) else v2_crypt(data, key)


ALGOS = {"rc4": rc4, "aisuru_v2": _v2}


def decrypt(data, key, ctx):
    algo = str(ctx.meta.get("algo", "auto")).lower()
    if algo in ALGOS:
        return ALGOS[algo](data, key)
    if algo != "auto":
        raise ValueError(f"unknown algo {algo!r} in the rule meta (use 'rc4', 'aisuru_v2' or 'auto')")
    best = max(((text_score(fn(data, key)), -n, name) for n, (name, fn) in enumerate(ALGOS.items())))
    score, _, name = best
    ctx.notes.append(f"algo=auto picked {name}" if score >= 0.85 else
                     f"algo=auto: no algorithm gave readable text (closest: {name}) - check the key and the cipher")
    return ALGOS[name](data, key)
