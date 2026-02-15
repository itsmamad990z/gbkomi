from .encryption import encrypt, decrypt
from .keygen import generate_secure_key
import os

def telegram_encrypt(message: str | bytes, key: bytes) -> bytes:
    if isinstance(message, str):
        message = message.encode()
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ct = cipher.encrypt(nonce, message, None)
    return nonce + ct

def telegram_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    nonce, ct = ciphertext[:12], ciphertext[12:]
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ct, None)