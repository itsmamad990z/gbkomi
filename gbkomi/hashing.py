import os
import base64
import hmac
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


FORMAT_VERSION = b"GBKH1"


def _hash_data(data: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(data)
    return digest.finalize()


def hash_data(data: bytes) -> bytes:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    digest = _hash_data(data)
    token = FORMAT_VERSION + digest
    return base64.b64encode(token)


def verify_hash(data: bytes, token: bytes) -> bool:
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    raw = base64.b64decode(token)

    if not raw.startswith(FORMAT_VERSION):
        return False

    stored_hash = raw[len(FORMAT_VERSION):]
    new_hash = _hash_data(data)

    return hmac.compare_digest(stored_hash, new_hash)


def hash_with_salt(data: bytes, salt: bytes = None):
    if not isinstance(data, bytes):
        raise TypeError("Data must be bytes")

    if salt is None:
        salt = os.urandom(16)

    digest = _hash_data(salt + data)

    token = FORMAT_VERSION + salt + digest
    return base64.b64encode(token)


def verify_hash_with_salt(data: bytes, token: bytes) -> bool:
    raw = base64.b64decode(token)

    if not raw.startswith(FORMAT_VERSION):
        return False

    offset = len(FORMAT_VERSION)
    salt = raw[offset:offset + 16]
    stored_hash = raw[offset + 16:]

    new_hash = _hash_data(salt + data)

    return hmac.compare_digest(stored_hash, new_hash)
