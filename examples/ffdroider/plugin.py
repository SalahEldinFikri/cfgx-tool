"""FFDroider: strings are XOR-encrypted with a position-dependent key stream (i % 18 + 5)."""
from cfgx.crypto import is_text

FAMILY = "FFDroider"


def decrypt(data):                      # $data and $data2 are both fed through this
    return bytes(b ^ (i % 18 + 5) for i, b in enumerate(data))


def validate(plaintext):                # a wrong `push` decrypts to noise; real strings are text
    return is_text(plaintext)
