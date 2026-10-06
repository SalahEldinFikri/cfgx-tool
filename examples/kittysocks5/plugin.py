"""kittysocks5: every config entry is XORed with a repeating 16-byte key."""
from cfgx.crypto import xor

FAMILY = "kittysocks5"            # one family (one output folder) for all three rules


def decrypt(data, key):          # data <- each entry (length from R2 / $a2), key <- 16 bytes
    return xor(data, key)
