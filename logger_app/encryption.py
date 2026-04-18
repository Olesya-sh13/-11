"""
Модуль шифрования логов с использованием Fernet (симметричное шифрование)
"""

from cryptography.fernet import Fernet
import base64
from pathlib import Path

KEY_FILE = Path(__file__).parent / "data" / "secret.key"

def generate_key():
    """Генерирует новый ключ шифрования"""
    key = Fernet.generate_key()
    with open(KEY_FILE, 'wb') as f:
        f.write(key)
    return key

def load_key():
    """Загружает ключ шифрования из файла"""
    if not KEY_FILE.exists():
        return generate_key()
    with open(KEY_FILE, 'rb') as f:
        return f.read()

def encrypt_log(data: str) -> str:
    """Шифрует строку лога"""
    key = load_key()
    f = Fernet(key)
    encrypted = f.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted).decode('utf-8')

def decrypt_log(encrypted_data: str) -> str:
    """Расшифровывает строку лога"""
    key = load_key()
    f = Fernet(key)
    decrypted = f.decrypt(base64.b64decode(encrypted_data.encode('utf-8')))
    return decrypted.decode('utf-8')