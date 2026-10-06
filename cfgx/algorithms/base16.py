import base64
import binascii


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return base64.b16encode(data)


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    try:
        return base64.b16decode(data)
    except binascii.Error as e:
        raise ValueError("Invalid Base16 data") from e