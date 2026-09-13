def rc4(data, key):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if isinstance(key, str):
        key = key.encode("ascii")
    elif not isinstance(key, bytes):
        raise TypeError("Key must be bytes or string")

    if not key:
        raise ValueError("Key cannot be empty")

    state = list(range(256))
    j = 0

    # Key Scheduling Algorithm
    for i in range(256):
        j = (
            j
            + state[i]
            + key[i % len(key)]
        ) % 256

        state[i], state[j] = (
            state[j],
            state[i]
        )

    # Pseudo-Random Generation Algorithm
    result = bytearray()
    i = 0
    j = 0

    for byte in data:
        i = (i + 1) % 256
        j = (j + state[i]) % 256

        state[i], state[j] = (
            state[j],
            state[i]
        )

        keystream = state[
            (state[i] + state[j]) % 256
        ]

        result.append(byte ^ keystream)

    return bytes(result)