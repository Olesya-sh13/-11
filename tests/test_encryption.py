"""
Модульные тесты модуля шифрования (logger_app/encryption.py).

Проверяемые свойства:
  * корректность пары encrypt/decrypt (round-trip);
  * нечитаемость зашифрованных данных;
  * генерация и загрузка ключа;
  * устойчивость к повреждённым данным.

Эти тесты НЕ обращаются к БД, поэтому помечены как `unit`.
"""

import base64
import pytest

from logger_app import encryption


pytestmark = pytest.mark.unit


# ---------- ROUND-TRIP ----------

def test_encrypt_decrypt_roundtrip(sample_log_message):
    """encrypt → decrypt должны вернуть исходную строку."""
    encrypted = encryption.encrypt_log(sample_log_message)
    decrypted = encryption.decrypt_log(encrypted)
    assert decrypted == sample_log_message


@pytest.mark.parametrize("text", [
    "ASCII only text",
    "Кириллица: вход выполнен",
    "数字 中文 🔐",
    "",  # граничный случай — пустая строка
    "x" * 10_000,  # длинная строка
])
def test_encrypt_decrypt_various_inputs(text):
    """Шифрование должно корректно работать для разных кодировок и размеров."""
    assert encryption.decrypt_log(encryption.encrypt_log(text)) == text


# ---------- БЕЗОПАСНОСТЬ ----------

def test_encrypted_text_differs_from_plain(sample_log_message):
    """Зашифрованный текст не должен содержать исходные данные."""
    encrypted = encryption.encrypt_log(sample_log_message)
    assert sample_log_message not in encrypted
    assert "admin" not in encrypted


def test_encrypted_output_is_valid_base64(sample_log_message):
    """Результат функции — корректная base64-строка."""
    encrypted = encryption.encrypt_log(sample_log_message)
    # base64.b64decode выбрасывает ошибку на некорректной строке
    base64.b64decode(encrypted.encode("utf-8"))


# ---------- КЛЮЧ ----------

def test_load_key_returns_bytes():
    """Функция load_key должна возвращать байтовый ключ."""
    key = encryption.load_key()
    assert isinstance(key, bytes)
    assert len(key) > 0


def test_two_loads_return_same_key():
    """Повторная загрузка должна давать тот же ключ (идемпотентность)."""
    assert encryption.load_key() == encryption.load_key()


# ---------- ОБРАБОТКА ОШИБОК ----------

def test_decrypt_invalid_data_raises():
    """Расшифровка некорректных данных должна выбрасывать исключение."""
    with pytest.raises(Exception):
        encryption.decrypt_log("это_не_зашифрованная_строка!!!")


def test_decrypt_tampered_data_raises(sample_log_message):
    """Изменение зашифрованных данных должно ломать расшифровку."""
    encrypted = encryption.encrypt_log(sample_log_message)
    # Подменяем один символ в середине
    tampered = encrypted[:-4] + "AAAA"
    with pytest.raises(Exception):
        encryption.decrypt_log(tampered)
