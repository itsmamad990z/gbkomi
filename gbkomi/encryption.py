import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

FORMAT_VERSION = b"GBK1"


def _validate_key(key: bytes):
    if not isinstance(key, bytes):
        raise TypeError("Key must be bytes")

    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")


def encrypt(data: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    _validate_key(key)

    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, data, associated_data)

    token = FORMAT_VERSION + nonce + ciphertext
    return base64.b64encode(token)


def decrypt(token: bytes, key: bytes, associated_data: bytes = None) -> bytes:
    _validate_key(key)

    raw = base64.b64decode(token)

    if not raw.startswith(FORMAT_VERSION):
        raise ValueError("Unsupported ciphertext format")

    nonce = raw[4:16]
    ciphertext = raw[16:]

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)