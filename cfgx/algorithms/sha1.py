import hashlib


def digest(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return hashlib.sha1(data).digest()


def hexdigest(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return hashlib.sha1(data).hexdigest()