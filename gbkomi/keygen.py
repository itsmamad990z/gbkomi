import os

def generate_secure_key(length: int = 32) -> bytes:
    """Generate secure random key for AES-256 or ChaCha20"""
    return os.urandom(length)