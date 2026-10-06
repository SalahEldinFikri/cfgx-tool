from Crypto.Cipher import DES


def _create_cipher(key, iv=None):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) != 8:
        raise ValueError("DES key must be 8 bytes")

    if iv is None:
        return DES.new(
            key,
            DES.MODE_ECB
        )

    if len(iv) != 8:
        raise ValueError("DES IV must be 8 bytes")

    return DES.new(
        key,
        DES.MODE_CBC,
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