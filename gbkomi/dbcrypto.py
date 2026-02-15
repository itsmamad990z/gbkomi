import json
from .encryption import context_encrypt, context_decrypt

def db_encrypt(data: dict, key: bytes) -> bytes:
    json_bytes = json.dumps(data).encode()
    return context_encrypt(json_bytes, key, context={"type": "db"})

def db_decrypt(cipher_text: bytes, key: bytes) -> dict:
    plain_bytes = context_decrypt(cipher_text, key, context={"type": "db"})
    return json.loads(plain_bytes.decode())