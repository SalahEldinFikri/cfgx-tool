def xor_rolling(data, key, increment=1):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(key, int):
        raise TypeError("Key must be an integer")

    if not 0 <= key <= 0xFF:
        raise ValueError("Key must be between 0 and 255")

    if not isinstance(increment, int):
        raise TypeError("Increment must be an integer")

    result = bytearray()
    current_key = key

    for byte in data:
        result.append(byte ^ current_key)
        current_key = (current_key + increment) & 0xFF

    return bytes(result)