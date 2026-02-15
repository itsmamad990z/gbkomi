from cryptography.fernet import Fernet
from .kdf import derive_key, generate_salt


CHUNK_SIZE = 64 * 1024


def encrypt_file(input_path: str, output_path: str, password: str) -> None:
    salt = generate_salt()
    key = derive_key(password, salt)
    f = Fernet(key)

    with open(input_path, "rb") as infile, open(output_path, "wb") as outfile:
        outfile.write(salt)

        while chunk := infile.read(CHUNK_SIZE):
            encrypted_chunk = f.encrypt(chunk)
            outfile.write(len(encrypted_chunk).to_bytes(4, "big"))
            outfile.write(encrypted_chunk)


def decrypt_file(input_path: str, output_path: str, password: str) -> None:
    with open(input_path, "rb") as infile:
        salt = infile.read(16)
        key = derive_key(password, salt)
        f = Fernet(key)

        with open(output_path, "wb") as outfile:
            while True:
                length_bytes = infile.read(4)
                if not length_bytes:
                    break

                length = int.from_bytes(length_bytes, "big")
                encrypted_chunk = infile.read(length)

                decrypted_chunk = f.decrypt(encrypted_chunk)
                outfile.write(decrypted_chunk)

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

def generate_nonce():
    return os.urandom(12)

def encrypt_file_stream(input_path: str, output_path: str, key: bytes, chunk_size: int = 64*1024):
    aesgcm = AESGCM(key)
    nonce = generate_nonce()
    with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(nonce)
        while chunk := f_in.read(chunk_size):
            encrypted = aesgcm.encrypt(nonce, chunk, None)
            f_out.write(encrypted)

def decrypt_file_stream(input_path: str, output_path: str, key: bytes, chunk_size: int = 64*1024):
    with open(input_path, 'rb') as f_in:
        nonce = f_in.read(12)
        aesgcm = AESGCM(key)
        with open(output_path, 'wb') as f_out:
            while chunk := f_in.read(chunk_size + 16):
                decrypted = aesgcm.decrypt(nonce, chunk, None)
                f_out.write(decrypted)