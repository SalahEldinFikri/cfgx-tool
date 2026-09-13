from Crypto.Cipher import ChaCha20_Poly1305


def encrypt(data, key, nonce=None, associated_data=None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) != 32:
        raise ValueError(
            "ChaCha20-Poly1305 key must be 32 bytes"
        )

    cipher = ChaCha20_Poly1305.new(
        key=key,
        nonce=nonce
    )

    if associated_data is not None:
        if not isinstance(associated_data, bytes):
            raise TypeError(
                "Associated data must be bytes"
            )

        cipher.update(associated_data)

    ciphertext, tag = cipher.encrypt_and_digest(data)

    return ciphertext, tag, cipher.nonce


def decrypt(
    data,
    key,
    tag,
    nonce,
    associated_data=None
):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) != 32:
        raise ValueError(
            "ChaCha20-Poly1305 key must be 32 bytes"
        )

    if not isinstance(tag, bytes):
        raise TypeError("Tag must be bytes")

    if not isinstance(nonce, bytes):
        raise TypeError("Nonce must be bytes")

    cipher = ChaCha20_Poly1305.new(
        key=key,
        nonce=nonce
    )

    if associated_data is not None:
        if not isinstance(associated_data, bytes):
            raise TypeError(
                "Associated data must be bytes"
            )

        cipher.update(associated_data)

    return cipher.decrypt_and_verify(
        data,
        tag
    )