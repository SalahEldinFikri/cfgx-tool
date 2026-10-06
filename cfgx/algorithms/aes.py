from Crypto.Cipher import AES


def _create_cipher(key, mode, iv=None):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) not in (16, 24, 32):
        raise ValueError(
            "AES key must be 16, 24, or 32 bytes"
        )

    mode = mode.upper()

    if mode == "ECB":
        return AES.new(key, AES.MODE_ECB)

    if mode == "CBC":
        if iv is None or len(iv) != 16:
            raise ValueError(
                "CBC requires a 16-byte IV"
            )

        return AES.new(
            key,
            AES.MODE_CBC,
            iv
        )

    if mode == "CTR":
        if iv is None:
            raise ValueError(
                "CTR requires an IV/nonce"
            )

        return AES.new(
            key,
            AES.MODE_CTR,
            nonce=iv
        )

    raise ValueError(
        f"Unsupported AES mode: {mode}"
    )


def encrypt(data, key, mode="ECB", iv=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    cipher = _create_cipher(key, mode, iv)

    return cipher.encrypt(data)


def decrypt(data, key, mode="ECB", iv=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    cipher = _create_cipher(key, mode, iv)

    return cipher.decrypt(data)