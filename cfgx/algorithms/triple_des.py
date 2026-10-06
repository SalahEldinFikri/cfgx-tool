from Crypto.Cipher import DES3


def _create_cipher(key, iv=None):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) not in (16, 24):
        raise ValueError(
            "3DES key must be 16 or 24 bytes"
        )

    if iv is None:
        return DES3.new(
            key,
            DES3.MODE_ECB
        )

    if len(iv) != 8:
        raise ValueError(
            "3DES IV must be 8 bytes"
        )

    return DES3.new(
        key,
        DES3.MODE_CBC,
        iv
    )


def encrypt(data, key, iv=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return _create_cipher(key, iv).encrypt(data)


def decrypt(data, key, iv=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return _create_cipher(key, iv).decrypt(data)