"""
Тесты модели User (logger_app/models.py).

Используется фикстура `db` из pytest-django — она открывает транзакцию
для теста и откатывает её в конце, обеспечивая изоляцию.
"""

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError

User = get_user_model()
pytestmark = pytest.mark.integration


def test_create_user_with_role(db):
    """Создание пользователя с указанной ролью."""
    user = User.objects.create_user(
        username="ivan", password="secret", role="admin"
    )
    assert user.pk is not None
    assert user.username == "ivan"
    assert user.role == "admin"
    assert user.check_password("secret")


def test_user_str_contains_username_and_role(admin_user):
    """__str__ должен возвращать строку с именем и ролью."""
    text = str(admin_user)
    assert admin_user.username in text
    assert "Администратор" in text


def test_username_must_be_unique(db):
    """БД должна отвергать повторяющиеся имена пользователей."""
    User.objects.create_user(username="dup", password="p1")
    with pytest.raises(IntegrityError):
        User.objects.create_user(username="dup", password="p2")


@pytest.mark.parametrize("role,label", [
    ("admin", "Администратор"),
    ("auditor", "Аудитор"),
])
def test_role_display_labels(db, role, label):
    """get_role_display должен возвращать русскоязычную метку."""
    user = User.objects.create_user(username=f"u_{role}", password="x", role=role)
    assert user.get_role_display() == label


def test_password_is_hashed(db):
    """Пароль не должен храниться в открытом виде."""
    user = User.objects.create_user(username="hashed", password="my_plain_pwd")
    assert user.password != "my_plain_pwd"
    assert user.check_password("my_plain_pwd")
