# Django Security Logger App

A Django web application that simulates and monitors security events for virtual machines, featuring role-based access control, encrypted logs, and analytics dashboard.

## Architecture

- **Framework**: Django 5.0.2
- **Database**: SQLite (`db.sqlite3`)
- **Python**: 3.10

## Project Structure

```
manage.py                    # Django CLI entry point
db.sqlite3                   # SQLite database
django_project/              # Django project config
  settings.py                # App settings, installed apps, DB config
  urls.py                    # Root URL routing
  wsgi.py / asgi.py          # WSGI/ASGI entry points
logger_app/                  # Main application
  models.py                  # Custom User model (extends AbstractUser)
  views.py                   # All views (dashboard, event log, encrypted logs, settings)
  urls.py                    # App-level URL routing
  admin.py                   # Django admin config
  encryption.py              # Fernet-based log encryption/decryption
  data/
    utils.py                 # Security simulation logic (pandas/numpy)
    secret.key               # Encryption key
  migrations/
    policy.json              # Access control policy config
  logs/                      # Encrypted log files (.enc)
  templates/logger_app/      # HTML templates
```

## Key Features

- **Custom User Model**: Extends `AbstractUser` with `role` field (admin/auditor)
- **Login/Logout**: Custom authentication views at `/logger/login/`
- **Dashboard**: Security event statistics, charts, anomaly detection
- **Event Log**: Paginated list of all access events with filtering
- **Encrypted Logs**: Admin-only view of Fernet-encrypted log files
- **Settings**: Admin-only panel to adjust policy parameters

## User Roles

- `admin` — Full access (dashboard, events, encrypted logs, settings)
- `auditor` — Read-only access (dashboard, events only)

## Access Policy

Defined in `logger_app/migrations/policy.json`. Controls which users can read/write which VMs. Configurable via the Settings page (admin only).

## Dependencies

- Django ^5.0
- pandas
- numpy
- cryptography (Fernet symmetric encryption)

## Running the App

The app runs on port 5000:
```
python manage.py runserver 0.0.0.0:5000
```

## URL Structure

- `/` → redirects to `/logger/`
- `/logger/` → dashboard
- `/logger/events/` → event log
- `/logger/encrypted-logs/` → encrypted logs (admin only)
- `/logger/settings/` → policy settings (admin only)
- `/logger/login/` → login page
- `/logger/logout/` → logout
- `/admin/` → Django admin panel

## Автоматизированное модульное тестирование

Используется фреймворк **pytest** + плагин **pytest-django**.

Структура:
- `pytest.ini` — конфигурация (settings module, маркеры, пути)
- `tests/conftest.py` — общие фикстуры (admin_user, auditor_user, sample_log_message)
- `tests/test_encryption.py` — модульные тесты шифрования (round-trip, параметризация, ошибки)
- `tests/test_models.py` — тесты модели User (создание, уникальность, роли)
- `tests/test_views.py` — интеграционные тесты HTTP-представлений (Django test client)

Запуск:
```bash
python -m pytest                    # все тесты
python -m pytest -m unit            # только чистые юнит-тесты
python -m pytest tests/test_encryption.py -v
```
