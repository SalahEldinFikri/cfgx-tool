from Crypto.Cipher import Blowfish


def _create_cipher(key, iv=None):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if not 4 <= len(key) <= 56:
        raise ValueError(
            "Blowfish key must be between 4 and 56 bytes"
        )

    if iv is None:
        return Blowfish.new(
            key,
            Blowfish.MODE_ECB
        )

    if len(iv) != 8:
        raise ValueError(
            "Blowfish IV must be 8 bytes"
        )

    return Blowfish.new(
        key,
        Blowfish.MODE_CBC,
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