import base64
import binascii


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return base64.b32encode(data)


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    try:
        return base64.b32decode(data)
    except binascii.Error as e:
        raise ValueError("Invalid Base32 data") from e