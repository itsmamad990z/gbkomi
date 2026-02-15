from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
import os
from .exceptions import EncryptionError, DecryptionError

def encrypt(message: bytes | str, password: str, algorithm: str = "AES-GCM") -> bytes:
    if isinstance(message, str):
        message = message.encode()
    try:
        key = derive_key(password)
        nonce = os.urandom(12)
        if algorithm == "AES-GCM":
            cipher = AESGCM(key)
        elif algorithm == "ChaCha20":
            cipher = ChaCha20Poly1305(key)
        else:
            raise EncryptionError("Unsupported algorithm")
        ct = cipher.encrypt(nonce, message, None)
        return nonce + ct
    except Exception as e:
        raise EncryptionError(str(e))

def decrypt(ciphertext: bytes, password: str, algorithm: str = "AES-GCM") -> bytes:
    try:
        key = derive_key(password)
        nonce, ct = ciphertext[:12], ciphertext[12:]
        if algorithm == "AES-GCM":
            cipher = AESGCM(key)
        elif algorithm == "ChaCha20":
            cipher = ChaCha20Poly1305(key)
        else:
            raise DecryptionError("Unsupported algorithm")
        return cipher.decrypt(nonce, ct, None)
    except Exception as e:
        raise DecryptionError(str(e))

# helper function to derive key using Argon2id
from .kdf import derive_key

import json

def generate_nonce():
    return os.urandom(12)

def context_encrypt(message: bytes, key: bytes, context: dict) -> bytes:
    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    context_bytes = json.dumps(context).encode()
    ct = aesgcm.encrypt(nonce, message, context_bytes)
    return nonce + ct

def context_decrypt(cipher_text: bytes, key: bytes, context: dict) -> bytes:
    aesgcm = AESGCM(key)
    nonce = cipher_text[:12]
    ct = cipher_text[12:]
    context_bytes = json.dumps(context).encode()
    return aesgcm.decrypt(nonce, ct, context_bytes)