import os
import base64
import secrets
import hmac
import json
import time
import uuid
from typing import Optional, List, Dict, Any
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import logging

logger = logging.getLogger("GBLog")
logger.setLevel(logging.INFO)
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

FORMAT_VERSION = b"GBL3"
MAX_RETRIES_DEFAULT = 5
BLOCK_DURATION = 600

class HMACVerificationError(Exception):
    pass

class AESDecryptionError(Exception):
    pass

class RetryLimitError(Exception):
    pass

class GBLog:
    def __init__(self, password: bytes, retry_file: Optional[str] = None, max_retries: int = MAX_RETRIES_DEFAULT):
        if not password or len(password) < 8:
            raise ValueError("Password must be at least 8 bytes")
        self.password = password
        self.retry_store: Dict[str, Dict[str, Any]] = {}
        self.retry_file = retry_file
        self.max_retries = max_retries
        if self.retry_file and os.path.exists(self.retry_file):
            try:
                with open(self.retry_file, "rb") as f:
                    encrypted_data = f.read()
                    self.retry_store = json.loads(self._decrypt_retry_store(encrypted_data))
            except Exception:
                self.retry_store = {}

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

    def _encrypt_retry_store(self, data: Dict[str, Any]) -> bytes:
        plaintext = json.dumps(data).encode()
        key, salt = self._derive_key()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=b"retry_store")
        secure_blob = FORMAT_VERSION + salt + nonce + ciphertext
        del plaintext, key, nonce, ciphertext
        return secure_blob

    def _decrypt_retry_store(self, blob: bytes) -> str:
        if not blob.startswith(FORMAT_VERSION):
            raise ValueError("Unsupported retry store version")
        offset = len(FORMAT_VERSION)
        salt = blob[offset:offset+16]
        nonce = blob[offset+16:offset+28]
        ciphertext = blob[offset+28:]
        key, _ = self._derive_key(salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=b"retry_store")
        except Exception as e:
            raise AESDecryptionError("Retry store decryption failed") from e
        result = plaintext.decode()
        del key, plaintext, nonce, ciphertext
        return result

    def _save_retry_store(self):
        if self.retry_file:
            encrypted_data = self._encrypt_retry_store(self.retry_store)
            tmp_file = self.retry_file + ".tmp"
            with open(tmp_file, "wb") as f:
                f.write(encrypted_data)
            os.replace(tmp_file, self.retry_file)

    def _encrypt_entry(self, message: str, associated_data: bytes) -> bytes:
        if not associated_data:
            raise ValueError("associated_data must be provided for tampering protection")
        entry_dict = {
            "id": str(uuid.uuid4()),
            "timestamp": int(time.time()),
            "message": message
        }
        plaintext = json.dumps(entry_dict).encode()
        key, salt = self._derive_key()
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=associated_data)
        secure_entry = FORMAT_VERSION + salt + nonce + ciphertext
        del plaintext, key, nonce, ciphertext
        return base64.b64encode(secure_entry)

    def append_log(self, filename: str, message: str, associated_data: bytes):
        entry = self._encrypt_entry(message, associated_data=associated_data)
        with open(filename, "ab") as f:
            f.write(entry + b"\n")
        logger.info("Secure log entry added")

    def _decrypt_entry(self, blob: bytes, associated_data: bytes) -> Dict[str, Any]:
        raw = base64.b64decode(blob)
        if not raw.startswith(FORMAT_VERSION):
            raise ValueError("Unsupported .gblog version")
        offset = len(FORMAT_VERSION)
        salt = raw[offset:offset + 16]
        nonce = raw[offset + 16: offset + 28]
        ciphertext = raw[offset + 28:]
        key, _ = self._derive_key(salt)
        aesgcm = AESGCM(key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=associated_data)
        except Exception as e:
            raise AESDecryptionError("AES decryption failed") from e
        entry = json.loads(plaintext.decode())
        del key, nonce, ciphertext, plaintext
        return entry

    def read_logs(self, filename: str, associated_data: bytes) -> List[Dict[str, Any]]:
        if not os.path.exists(filename):
            return []
        logs = []
        with open(filename, "rb") as f:
            lines = f.readlines()
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                log_entry = self._decrypt_entry(line, associated_data=associated_data)
                logs.append(log_entry)
            except Exception as e:
                logger.warning("Skipping corrupted log entry: %s", str(e))
                continue
        logger.info("All log entries loaded securely")
        return logs

    def clear_logs(self, filename: str):
        if os.path.exists(filename):
            os.remove(filename)
            logger.info("Log file cleared securely")

    def decrypt_with_retry(self, blob: bytes, bot_id: str, associated_data: bytes):
        now = time.time()
        entry = self.retry_store.get(bot_id, {"fail_count": 0, "last_fail_time": 0})
        if entry["fail_count"] >= self.max_retries and now - entry["last_fail_time"] < BLOCK_DURATION:
            raise RetryLimitError(f"Bot {bot_id} temporarily blocked due to repeated failed attempts")
        try:
            data = self._decrypt_entry(blob, associated_data=associated_data)
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
            raise RetryLimitError(f"Failed attempt {entry['fail_count']} for bot {bot_id}")

    def clear_retry_store(self):
        self.retry_store = {}
        if self.retry_file and os.path.exists(self.retry_file):
            os.remove(self.retry_file)
