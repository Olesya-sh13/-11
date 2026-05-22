"""
Интеграционные тесты HTTP-представлений (logger_app/views.py).

Используется встроенный в Django Client (фикстура `client` из pytest-django),
который имитирует HTTP-запросы без реального сервера.
"""

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.views]


# ---------- ЛОГИН / АВТОРИЗАЦИЯ ----------

def test_login_page_returns_200(client):
    """GET страницы логина должен возвращать 200."""
    response = client.get("/logger/login/")
    assert response.status_code == 200


def test_login_with_valid_credentials_redirects(client, admin_user):
    """Успешный логин должен перенаправить на дашборд с токеном в URL."""
    response = client.post("/logger/login/", {
        "username": admin_user.username,
        "password": "admin_pass_123",
    })
    assert response.status_code == 302
    assert "/logger/" in response.url
    assert "t=" in response.url  # токен в URL


def test_login_with_invalid_credentials_does_not_redirect(client, admin_user):
    """Неверный пароль не должен выдавать токен и не должен редиректить на дашборд."""
    response = client.post("/logger/login/", {
        "username": admin_user.username,
        "password": "wrong_password",
    })
    # При неудачной авторизации страница входа отображается заново (200),
    # а не выполняется редирект (302) на защищённый ресурс.
    assert response.status_code == 200
    # Форма входа должна остаться на экране
    assert b'name="password"' in response.content


# ---------- ДОСТУП БЕЗ АВТОРИЗАЦИИ ----------

def test_dashboard_requires_authentication(client):
    """Без токена доступ к дашборду должен перенаправлять на логин."""
    response = client.get("/logger/")
    assert response.status_code == 302
    assert "/logger/login/" in response.url


def test_event_log_requires_authentication(client):
    """Без токена доступ к журналу событий должен перенаправлять на логин."""
    response = client.get("/logger/events/")
    assert response.status_code == 302


# ---------- ДОСТУП АВТОРИЗОВАННЫХ ----------

def _login_and_get_token(client, username, password):
    """Хелпер: входит в систему и возвращает токен из URL редиректа."""
    response = client.post(
        "/logger/login/", {"username": username, "password": password}
    )
    return response.url.split("t=")[1]


def test_admin_can_access_dashboard(client, admin_user):
    """Администратор должен видеть дашборд."""
    token = _login_and_get_token(client, "admin_test", "admin_pass_123")
    response = client.get(f"/logger/?t={token}")
    assert response.status_code == 200


def test_auditor_redirected_from_admin_only_page(client, auditor_user):
    """Аудитор не должен иметь доступ к зашифрованным логам."""
    token = _login_and_get_token(client, "auditor_test", "auditor_pass_123")
    response = client.get(f"/logger/encrypted-logs/?t={token}")
    # admin_required редиректит не-админа
    assert response.status_code == 302


def test_admin_can_access_encrypted_logs(client, admin_user):
    """Администратор должен иметь доступ к странице зашифрованных логов."""
    token = _login_and_get_token(client, "admin_test", "admin_pass_123")
    response = client.get(f"/logger/encrypted-logs/?t={token}")
    assert response.status_code == 200
