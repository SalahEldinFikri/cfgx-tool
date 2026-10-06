"""One flat import for everything a plugin usually needs::

    from cfgx.crypto import rc4, xor, aes_decrypt, b64decode

All functions take and return ``bytes``.
"""
from __future__ import annotations

from .algorithms import base16 as _b16
from .algorithms import base32 as _b32
from .algorithms import base45 as _b45
from .algorithms import base58 as _b58
from .algorithms import base64 as _b64
from .algorithms import base85 as _b85
from .algorithms import aes as _aes
from .algorithms import blowfish as _blowfish
from .algorithms import chacha20 as _chacha20
from .algorithms import chacha20_poly1305 as _chacha20_poly1305
from .algorithms import des as _des
from .algorithms import md5 as _md5
from .algorithms import sha1 as _sha1
from .algorithms import sha256 as _sha256
from .algorithms import triple_des as _triple_des
from .algorithms.rc4 import rc4
from .algorithms.xor import xor, xor_single_byte
from .algorithms.xor_rolling import xor_rolling
from .output import decode_text as _decode_text
from .output import score_plaintext as text_score   # 0..1: how much like readable text

# ---- ciphers ---------------------------------------------------------------
aes_decrypt = _aes.decrypt              # (data, key, mode="ECB", iv=None)
des_decrypt = _des.decrypt              # (data, key, iv=None)
des3_decrypt = _triple_des.decrypt      # (data, key, iv=None)
blowfish_decrypt = _blowfish.decrypt    # (data, key, iv=None)
chacha20_decrypt = _chacha20.decrypt    # (data, key, nonce=None)
chacha20_poly1305_decrypt = _chacha20_poly1305.decrypt

# ---- encodings -------------------------------------------------------------
b16decode = _b16.decode
b32decode = _b32.decode
b45decode = _b45.decode
b58decode = _b58.decode
b64decode = _b64.decode
b85decode = _b85.decode
a85decode = _b85.ascii85_decode

# ---- hashes (handy for deriving keys) --------------------------------------
md5 = _md5.digest
sha1 = _sha1.digest
sha256 = _sha256.digest


def unpad_pkcs7(data: bytes) -> bytes:
    """Strip PKCS#7 padding if it is valid, otherwise return the data unchanged."""
    if not data:
        return data
    n = data[-1]
    if 1 <= n <= 16 and data.endswith(bytes([n]) * n):
        return data[:-n]
    return data


def is_text(data: bytes, min_ratio: float = 0.95) -> bool:
    """True if ``data`` decodes (UTF-8 / UTF-16LE) to mostly printable text.
    Handy in ``validate()`` to reject wrong key/data combinations."""
    return _decode_text(data, min_ratio) is not None


__all__ = [n for n in dir() if not n.startswith("_") and n != "annotations"]
