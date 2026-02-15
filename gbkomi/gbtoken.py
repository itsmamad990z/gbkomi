import json
from .encryption import context_encrypt, context_decrypt
import os

def gbtoken_create(filename: str, key: bytes, data: dict):
    cipher = context_encrypt(json.dumps(data).encode(), key, context={"type": "gbtoken"})
    with open(filename, 'wb') as f:
        f.write(cipher)

def gbtoken_read(filename: str, key: bytes) -> dict:
    with open(filename, 'rb') as f:
        cipher = f.read()
    plain_bytes = context_decrypt(cipher, key, context={"type": "gbtoken"})
    return json.loads(plain_bytes.decode())

def gbtoken_update(filename: str, key: bytes, data: dict):
    existing = {}
    try:
        existing = gbtoken_read(filename, key)
    except Exception:
        pass
    existing.update(data)
    gbtoken_create(filename, key, existing)