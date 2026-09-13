import base64
import binascii


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return base64.b85encode(data)


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    try:
        return base64.b85decode(data)
    except binascii.Error as e:
        raise ValueError("Invalid Base85 data") from e


def ascii85_encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return base64.a85encode(data)


def ascii85_decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    try:
        return base64.a85decode(data)
    except ValueError as e:
        raise ValueError("Invalid ASCII85 data") from e