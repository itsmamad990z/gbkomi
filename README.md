# gbkomi v1.4.1

**gbkomi** is a high-security Python library for encryption, hashing, secure database storage, and Telegram bot token management.  

It is designed for small to large projects and provides **industrial-strength encryption** tailored for secure Telegram bots.

---

## 🔹 Key Features

---

### 1️⃣ Context-aware Message Encryption

- Encrypt messages with additional metadata such as `chat_id`, `message_id`, and `timestamp`.  
- Prevents replay attacks and ensures message security for each unique context.

**Example:**
```python
from gbkomi import context_encrypt, context_decrypt, generate_secure_key

key = generate_secure_key()
message = b"Sensitive message"
context = {"chat_id": 12345, "message_id": 678, "timestamp": 1700000000}

cipher = context_encrypt(message, key, context)
plain = context_decrypt(cipher, key, context)
print(plain.decode())
2️⃣ Streaming Secure File Encryption
Encrypt and decrypt large files efficiently without loading them fully into memory.

Supports files >100MB.

Example:

from gbkomi import encrypt_file_stream, decrypt_file_stream, generate_secure_key

key = generate_secure_key()
encrypt_file_stream("video.mp4", "video.enc", key)
decrypt_file_stream("video.enc", "video_decoded.mp4", key)
3️⃣ Secure Database Layer
Store all database records securely using AES-256-GCM and HMAC verification.

Works with SQLite, PostgreSQL, and MySQL.

Tamper-proof and safe even if the database is compromised.

Example:

from gbkomi import db_encrypt, db_decrypt, generate_secure_key

key = generate_secure_key()
data = {"balance": 1000, "settings": {"theme": "dark"}}

cipher = db_encrypt(data, key)
plain = db_decrypt(cipher, key)
print(plain)
4️⃣ Secure Telegram Bot Token Management
.gbtoken file replaces .env for secure bot token storage.

Encrypted with AES-256-GCM and verified with HMAC.

Context-aware: tokens can be limited per project/user.

Example:

from gbkomi import gbtoken_create, gbtoken_read, generate_secure_key

key = generate_secure_key()
gbtoken_create(".gbtoken", key, {"telegram_bot_token": "123456:ABC-DEF"})

tokens = gbtoken_read(".gbtoken", key)
bot_token = tokens["telegram_bot_token"]
print(bot_token)
🔹 Installation
pip install gbkomi==1.4.1
🔹 Using gbkomi with a Telegram Bot (Step-by-Step)
1️⃣ Create a project folder
mkdir gbkomi_bot_demo
cd gbkomi_bot_demo
2️⃣ Set up a Python environment
python -m venv venv
venv\Scripts\activate      # Windows
source venv/bin/activate   # Linux / Mac
pip install gbkomi telebot
3️⃣ Create .gbtoken securely
from gbkomi import gbtoken_create, generate_secure_key

key = generate_secure_key()
bot_token = input("Enter your Telegram Bot Token: ")
gbtoken_create(".gbtoken", key, {"telegram_bot_token": bot_token})
The .gbtoken file is encrypted and tamper-proof.

Store key securely — without it, the bot token cannot be read.

4️⃣ Build a secure Telegram bot
Use telebot (PyTelegramBotAPI) and gbkomi functions.

Encrypt user messages with context_encrypt.

Store encrypted messages in a secure database with db_encrypt.

Encrypt large files sent by users with encrypt_file_stream.

Example Bot Skeleton:

import telebot
from gbkomi import gbtoken_read, context_encrypt, context_decrypt, db_encrypt, db_decrypt, generate_secure_key

key = open("data/key.bin", "rb").read()
tokens = gbtoken_read(".gbtoken", key)
BOT_TOKEN = tokens["telegram_bot_token"]
bot = telebot.TeleBot(BOT_TOKEN)

db = {}

@bot.message_handler(commands=["start"])
def start(msg):
    bot.send_message(msg.chat.id, "Welcome to gbkomi secure bot!")
Full example with all features is available in the gbkomi_bot_demo repository.

🔹 Security Notes
Always protect your encryption key — without it, .gbtoken and encrypted data are inaccessible.

.gbtoken is much more secure than .env; even if the file is leaked, data is encrypted.

Rotate keys periodically for long-term deployments.

🔹 Supported Python Versions
Python 3.8+

Tested on Python 3.11

🔹 License
MIT License

🔹 Summary
gbkomi v1.4.1 provides industrial-strength encryption, context-aware message protection, secure file and database storage, and an advanced Telegram bot token management system.

Perfect for projects where security and reliability are critical.