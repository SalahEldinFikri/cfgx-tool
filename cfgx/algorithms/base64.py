import base64
import binascii


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return base64.b64encode(data)


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    try:
        return base64.b64decode(data, validate=True)
    except binascii.Error as e:
        raise ValueError("Invalid Base64 data") from e