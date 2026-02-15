from argon2 import PasswordHasher
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes

def derive_key(password: str, length: int = 32) -> bytes:
    password_bytes = password.encode()
    salt = b"gbkomi_salt_2026"
    kdf = Argon2id(
        time_cost=3,
        memory_cost=64*1024,
        parallelism=4,
        length=length,
        salt=salt,
        backend=default_backend()
    )
    return kdf.derive(password_bytes)