from Crypto.Cipher import ChaCha20


def _create_cipher(key, nonce=None):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) != 32:
        raise ValueError(
            "ChaCha20 key must be 32 bytes"
        )

    if nonce is None:
        return ChaCha20.new(key=key)

    if len(nonce) not in (8, 12, 24):
        raise ValueError(
            "ChaCha20 nonce must be 8, 12, or 24 bytes"
        )

    return ChaCha20.new(
        key=key,
        nonce=nonce
    )


def encrypt(data, key, nonce=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return _create_cipher(key, nonce).encrypt(data)


def decrypt(data, key, nonce=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    return _create_cipher(key, nonce).decrypt(data)