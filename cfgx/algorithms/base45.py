ALPHABET = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"


def encode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    result = bytearray()

    for i in range(0, len(data), 2):
        if i + 1 < len(data):
            value = data[i] * 256 + data[i + 1]

            e = value % 45
            value //= 45

            d = value % 45
            value //= 45

            c = value % 45

            result.extend((
                ALPHABET[e],
                ALPHABET[d],
                ALPHABET[c],
            ))
        else:
            value = data[i]

            e = value % 45
            value //= 45

            d = value % 45

            result.extend((
                ALPHABET[e],
                ALPHABET[d],
            ))

    return bytes(result)


def decode(data):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    values = {
        char: index
        for index, char in enumerate(ALPHABET)
    }

    result = bytearray()
    index = 0

    while index < len(data):

        if index + 2 < len(data):
            try:
                a = values[data[index]]
                b = values[data[index + 1]]
                c = values[data[index + 2]]
            except KeyError as e:
                raise ValueError(
                    "Invalid Base45 character"
                ) from e

            value = a + b * 45 + c * 45 * 45

            if value > 0xFFFF:
                raise ValueError("Invalid Base45 value")

            result.append(value // 256)
            result.append(value % 256)

            index += 3

        elif index + 1 < len(data):
            try:
                a = values[data[index]]
                b = values[data[index + 1]]
            except KeyError as e:
                raise ValueError(
                    "Invalid Base45 character"
                ) from e

            value = a + b * 45

            if value > 0xFF:
                raise ValueError("Invalid Base45 value")

            result.append(value)

            index += 2

        else:
            raise ValueError("Invalid Base45 length")

    return bytes(result)