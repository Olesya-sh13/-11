"""
Глобальные фикстуры pytest, доступные во всех тестовых модулях.

Фикстуры — это переиспользуемые объекты-окружения для тестов
(аналог setUp/tearDown в unittest, но более гибкий).
"""

import pytest
from django.contrib.auth import get_user_model

User = get_user_model()


@pytest.fixture
def admin_user(db):
    """Создаёт пользователя с ролью администратора."""
    return User.objects.create_user(
        username="admin_test",
        password="admin_pass_123",
        role="admin",
    )


@pytest.fixture
def auditor_user(db):
    """Создаёт пользователя с ролью аудитора."""
    return User.objects.create_user(
        username="auditor_test",
        password="auditor_pass_123",
        role="auditor",
    )


@pytest.fixture
def sample_log_message():
    """Тестовое сообщение для проверки шифрования."""
    return "Пользователь admin вошёл в систему 2026-04-23 12:00:00"
