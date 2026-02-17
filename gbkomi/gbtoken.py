import os
import base64
import secrets
import json
import logging
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger("GBKomi")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

FORMAT_VERSION = b"GBT4"
MAX_RETRIES = 3
BLOCK_DURATION = 600

class AESDecryptionError(Exception):
    pass

class RetryLimitError(Exception):
    pass

class GBKomi:
    def __init__(self, password: bytes, retry_file: Optional[str] = None):
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 bytes")
        self.password = password
        self.retry_file = retry_file
        self.retry_store: Dict[str, Dict[str, Any]] = {}
        if self.retry_file and os.path.exists(self.retry_file):
            try:
                with open(self.retry_file, "r") as f:
                    self.retry_store = json.load(f)
            except Exception:
                self.retry_store = {}

    def _save_retry_store(self):
        if self.retry_file:
            tmp_file = self.retry_file + ".tmp"
            with open(tmp_file, "w") as f:
                json.dump(self.retry_store, f)
            os.replace(tmp_file, self.retry_file)

    def _derive_key(self, salt: Optional[bytes] = None):
        if salt is None:
            salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=500000
        )
        key = kdf.derive(self.password)
        return key, salt

    def encrypt_token(self, token_data: Dict[str, Any], associated_data: Optional[bytes] = None) -> bytes:
        if associated_data is None:
            associated_data = secrets.token_bytes(16)
        token_data = token_data.copy()
        token_data["token_id"] = secrets.token_hex(8)
        token_data["timestamp"] = int(time.time())
        plaintext = json.dumps(token_data).encode()
        key, salt = self._derive_key()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=associated_data)
        secure_blob = FORMAT_VERSION + salt + nonce + ciphertext
        del plaintext, key, nonce, ciphertext
        return base64.b64encode(secure_blob)

    def decrypt_token(self, blob: bytes, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        raw = base64.b64decode(blob)
        if not raw.startswith(FORMAT_VERSION):
            raise ValueError("Unsupported .gbtoken version")
        offset = len(FORMAT_VERSION)
        salt = raw[offset:offset+16]
        nonce = raw[offset+16:offset+28]
        ciphertext = raw[offset+28:]
        key, _ = self._derive_key(salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=associated_data)
        except Exception as e:
            raise AESDecryptionError("AES decryption failed") from e
        try:
            data = json.loads(plaintext.decode())
        except Exception as e:
            raise ValueError("JSON decoding failed") from e
        del key, plaintext, ciphertext, nonce
        return data

    def save_to_file(self, filename: str, token_data: Dict[str, Any], associated_data: Optional[bytes] = None):
        blob = self.encrypt_token(token_data, associated_data=associated_data)
        with open(filename, "wb") as f:
            f.write(blob)
        del blob

    def load_from_file(self, filename: str, associated_data: Optional[bytes] = None) -> Dict[str, Any]:
        with open(filename, "rb") as f:
            blob = f.read()
        data = self.decrypt_token(blob, associated_data=associated_data)
        del blob
        return data

    def decrypt_with_retry(self, blob: bytes, bot_id: str, associated_data: Optional[bytes] = None):
        now = time.time()
        entry = self.retry_store.get(bot_id, {"fail_count": 0, "last_fail_time": 0})
        if entry["fail_count"] >= MAX_RETRIES and now - entry["last_fail_time"] < BLOCK_DURATION:
            raise RetryLimitError(f"Token for {bot_id} temporarily blocked")
        try:
            data = self.decrypt_token(blob, associated_data=associated_data)
            entry["fail_count"] = 0
            entry["last_fail_time"] = 0
            self.retry_store[bot_id] = entry
            self._save_retry_store()
            return data
        except Exception:
            entry["fail_count"] += 1
            entry["last_fail_time"] = now
            self.retry_store[bot_id] = entry
            self._save_retry_store()
            raise RetryLimitError(f"Failed attempt {entry['fail_count']} for {bot_id}")

    def rotate_key(self, old_file: str, new_file: str, associated_data: Optional[bytes] = None):
        tokens = self.load_from_file(old_file, associated_data=associated_data)
        self.save_to_file(new_file, tokens, associated_data=associated_data)

    def clear_retry_store(self):
        self.retry_store = {}
        if self.retry_file and os.path.exists(self.retry_file):
            os.remove(self.retry_file)
