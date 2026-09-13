ALPHABET = (
    b"123456789ABCDEFGHJKLMNPQRSTUVWXYZ"
    b"abcdefghijkmnopqrstuvwxyz"
)


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not data:
        return b""

    leading_zeroes = len(data) - len(data.lstrip(b"\x00"))

    value = int.from_bytes(data, "big")
    result = bytearray()

    while value:
        value, remainder = divmod(value, 58)
        result.append(ALPHABET[remainder])

    result.reverse()

    return (
        ALPHABET[:1] * leading_zeroes
        + bytes(result)
    )


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not data:
        return b""

    values = {
        char: index
        for index, char in enumerate(ALPHABET)
    }

    value = 0

    for char in data:
        if char not in values:
            raise ValueError("Invalid Base58 character")

        value = value * 58 + values[char]

    if value == 0:
        raw = b""
    else:
        raw = value.to_bytes(
            (value.bit_length() + 7) // 8,
            "big"
        )

    leading_zeroes = len(data) - len(
        data.lstrip(ALPHABET[:1])
    )

    return b"\x00" * leading_zeroes + raw