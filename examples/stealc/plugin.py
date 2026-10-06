"""Stealc: every string is base64( RC4( text ) ), one RC4 key per build."""
from cfgx.crypto import b64decode, rc4, is_text

FAMILY = "Stealc"


def decrypt(data, key):          # data <- $data_32/$data_64, key <- $key_32/$key_64 (paired by suffix)
    return rc4(b64decode(data), key)


def validate(plaintext):         # a wrong reference decodes to noise; real Stealc strings are text
    return is_text(plaintext)
