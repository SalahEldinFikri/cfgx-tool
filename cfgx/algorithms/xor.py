def xor(data, key):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if not key:
        raise ValueError("Key cannot be empty")

    return bytes(
        byte ^ key[index % len(key)]
        for index, byte in enumerate(data)
    )


def xor_single_byte(data, key):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(key, int):
        raise TypeError("Key must be an integer")

    if not 0 <= key <= 0xFF:
        raise ValueError("Key must be between 0 and 255")

    return bytes(byte ^ key for byte in data)