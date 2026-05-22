"""
Скрипт измерения качества Security Logger по ГОСТ Р ИСО/МЭК 25010.

Разделы:
  1. Внутреннее качество  — статический анализ кода (без запуска)
  2. Внешнее качество     — функциональные и HTTP-тесты живого сервера
  3. Качество при использовании — сценарии реальных пользователей
  4. Автотесты pytest

Запуск:
    python quality_check.py

Сервер должен быть запущен (gunicorn на порту 5000).
"""

import ast
import os
import sys
import time
import json
import math
import subprocess
import threading
import urllib.request
import urllib.parse
import urllib.error
from http.client import HTTPConnection
from pathlib import Path
from datetime import datetime

# ─────────────────────────────────────────────────────────────────
BASE_HOST  = "localhost"
BASE_PORT  = 5000
BASE_URL   = f"http://{BASE_HOST}:{BASE_PORT}"
ADMIN_USER = "admin"
ADMIN_PASS = "Admin2024!"
SOURCE_DIR = Path("logger_app")
TESTS_DIR  = Path("tests")
# ─────────────────────────────────────────────────────────────────

SEP  = "─" * 62
SEP2 = "═" * 62


def hdr(title):
    print(f"\n{SEP2}")
    print(f"  {title}")
    print(SEP2)


def row(label, value, status=None):
    icons = {"ok": "✅", "warn": "⚠️ ", "fail": "❌", None: "   "}
    icon  = icons.get(status, "   ")
    print(f"  {icon} {label:<42} {value}")


def sep():
    print(f"  {SEP}")


# ── HTTP helpers (no redirect follow) ──────────────────────────

def _raw_request(method, path, body=None, headers=None):
    """Выполняет HTTP-запрос без автоматического следования редиректам.
    Возвращает (status_code, response_headers_dict, body_bytes, elapsed_sec).
    """
    h = HTTPConnection(BASE_HOST, BASE_PORT, timeout=8)
    hdrs = {"Host": f"{BASE_HOST}:{BASE_PORT}",
            "Connection": "close"}
    if headers:
        hdrs.update(headers)
    if body:
        hdrs["Content-Length"] = str(len(body))
    t0 = time.time()
    try:
        h.request(method, path, body=body, headers=hdrs)
        resp = h.getresponse()
        data = resp.read()
        elapsed = time.time() - t0
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, data, elapsed
    except Exception as e:
        return 0, {}, b"", time.time() - t0
    finally:
        h.close()


def http_get(path):
    """GET запрос, возвращает (code, body_bytes, elapsed_sec)."""
    code, _, body, elapsed = _raw_request("GET", path)
    return code, body, elapsed


def http_post(path, data_dict):
    """POST форм-данные, возвращает (code, headers_dict, elapsed_sec)."""
    body = urllib.parse.urlencode(data_dict).encode()
    code, headers, _, elapsed = _raw_request(
        "POST", path, body=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    return code, headers, elapsed


def get_auth_token(username=ADMIN_USER, password=ADMIN_PASS):
    """Логинится и возвращает токен из Location-заголовка."""
    code, headers, _, _ = _raw_request(
        "POST", "/logger/login/",
        body=urllib.parse.urlencode(
            {"username": username, "password": password}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    if code in (301, 302):
        loc = headers.get("location", "")
        if "t=" in loc:
            return loc.split("t=")[1].split("&")[0]
    return None


# ═══════════════════════════════════════════════════════════════════
# 1. ВНУТРЕННЕЕ КАЧЕСТВО — статический анализ кода
# ═══════════════════════════════════════════════════════════════════

def count_ast(filepath):
    """Считает функции, классы, строки через AST-анализ."""
    source = Path(filepath).read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return {}
    lines        = source.splitlines()
    total_lines  = len([l for l in lines if l.strip()])
    comments     = len([l for l in lines if l.strip().startswith("#")])
    docstrings   = sum(
        1 for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
        and ast.get_docstring(node)
    )
    functions    = sum(1 for n in ast.walk(tree)
                       if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)))
    classes      = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
    branches     = sum(
        1 for n in ast.walk(tree)
        if isinstance(n, (ast.If, ast.For, ast.While,
                          ast.Try, ast.ExceptHandler, ast.With))
    )
    return {
        "lines": total_lines, "comments": comments,
        "docstrings": docstrings, "functions": functions,
        "classes": classes, "branches": branches,
    }


def internal_quality():
    hdr("1. ВНУТРЕННЕЕ КАЧЕСТВО — статический анализ кода")

    modules = {
        "models.py":     SOURCE_DIR / "models.py",
        "views.py":      SOURCE_DIR / "views.py",
        "encryption.py": SOURCE_DIR / "encryption.py",
        "utils.py":      SOURCE_DIR / "data" / "utils.py",
        "admin.py":      SOURCE_DIR / "admin.py",
    }

    total_lines = total_comments = total_funcs = total_branches = 0
    total_docstrings = 0

    print(f"\n  {'Модуль':<18} {'Строк':>6} {'Коммент':>8} "
          f"{'Функций':>8} {'Ветвл.':>7} {'Докстр.':>8}")
    print(f"  {'─'*18} {'─'*6} {'─'*8} {'─'*8} {'─'*7} {'─'*8}")

    for name, path in modules.items():
        if not path.exists():
            continue
        s = count_ast(path)
        cpct = round(s["comments"] / max(s["lines"], 1) * 100)
        print(f"  {name:<18} {s['lines']:>6} {cpct:>7}% "
              f"{s['functions']:>8} {s['branches']:>7} {s['docstrings']:>8}")
        total_lines      += s["lines"]
        total_comments   += s["comments"]
        total_funcs      += s["functions"]
        total_branches   += s["branches"]
        total_docstrings += s["docstrings"]

    sep()

    comment_density = round(total_comments / max(total_lines, 1) * 100)
    avg_func_len    = round(total_lines / max(total_funcs, 1))
    branch_density  = round(total_branches / max(total_lines, 1) * 100)
    doc_ratio       = round(total_docstrings / max(total_funcs, 1) * 100)

    c_stat = "ok"   if comment_density >= 8  else ("warn" if comment_density >= 4  else "fail")
    f_stat = "ok"   if avg_func_len    <= 20 else ("warn" if avg_func_len    <= 40 else "fail")
    b_stat = "ok"   if branch_density  <= 15 else ("warn" if branch_density  <= 25 else "fail")
    d_stat = "ok"   if doc_ratio       >= 50 else ("warn" if doc_ratio       >= 30 else "fail")

    row("Плотность комментариев",           f"{comment_density}%",  c_stat)
    row("Средняя длина функции",            f"{avg_func_len} строк", f_stat)
    row("Плотность ветвлений (сложность)",  f"{branch_density}%",   b_stat)
    row("Функции с документацией",          f"{doc_ratio}%",         d_stat)
    row("Количество независимых модулей",   str(len(modules)),        "ok" if len(modules) >= 5 else "warn")

    score = round(
        (min(comment_density / 12, 1) * 25) +
        (min(20 / max(avg_func_len, 1), 1) * 25) +
        (min(15 / max(branch_density, 1), 1) * 25) +
        (min(doc_ratio / 70, 1) * 25)
    )
    sep()
    row("► ОЦЕНКА ВНУТРЕННЕГО КАЧЕСТВА",
        f"{score}/100",
        "ok" if score >= 65 else ("warn" if score >= 45 else "fail"))
    return score


# ═══════════════════════════════════════════════════════════════════
# 2. ВНЕШНЕЕ КАЧЕСТВО — функциональные и HTTP-тесты
# ═══════════════════════════════════════════════════════════════════

def external_quality():
    hdr("2. ВНЕШНЕЕ КАЧЕСТВО — функциональные и HTTP-тесты")
    results = []

    # 2.1 Доступность сервера
    print("\n  [ Доступность и аутентификация ]")
    code, body, elapsed = http_get("/logger/login/")
    ok_server = (code == 200)
    row("Сервер доступен (GET /logger/login/)",
        f"{code}  {elapsed*1000:.0f}ms",
        "ok" if ok_server else "fail")
    results.append(("Доступность сервера", ok_server))

    if not ok_server:
        row("Сервер не отвечает — запустите приложение", "", "fail")
        return 0

    # 2.2 Аутентификация
    token = get_auth_token()
    has_token = token is not None
    row("Аутентификация admin → токен в URL",
        "токен получен" if has_token else "ОШИБКА",
        "ok" if has_token else "fail")
    results.append(("Аутентификация admin", has_token))

    if not has_token:
        return 0

    # 2.3 Время отклика ключевых эндпоинтов
    print(f"\n  [ Время отклика эндпоинтов ]")
    endpoints = [
        ("Дашборд",           f"/logger/?t={token}"),
        ("Журнал событий",    f"/logger/events/?t={token}"),
        ("Шифрованные логи",  f"/logger/encrypted-logs/?t={token}"),
        ("Настройки",         f"/logger/settings/?t={token}"),
    ]
    times = []
    for label, path in endpoints:
        c, b, t = http_get(path)
        times.append(t)
        t_ms = t * 1000
        st   = "ok" if (c == 200 and t_ms < 800)  else \
               "warn" if (c == 200 and t_ms < 2000) else "fail"
        results.append((f"HTTP {label}", c == 200))
        row(f"GET {label}", f"{c}  {t_ms:.0f}ms", st)

    avg_ms = sum(times) / len(times) * 1000
    sep()
    row("Среднее время отклика",
        f"{avg_ms:.0f}ms",
        "ok" if avg_ms < 800 else ("warn" if avg_ms < 2000 else "fail"))

    # 2.4 Защита неавторизованного доступа
    print(f"\n  [ Безопасность — защита эндпоинтов ]")
    for label, path in [
        ("Дашборд без токена → 302",            "/logger/"),
        ("Журнал событий без токена → 302",     "/logger/events/"),
        ("Настройки без токена → 302",          "/logger/settings/"),
        ("Шифр. логи без токена → 302",         "/logger/encrypted-logs/"),
    ]:
        c, _, _ = http_get(path)
        ok = (c == 302)
        results.append((label, ok))
        row(label, f"HTTP {c}", "ok" if ok else "fail")

    # 2.5 Ролевое разграничение
    print(f"\n  [ Ролевое разграничение — аудитор vs администратор ]")
    aud_token = get_auth_token("Аудитор", "audit2024")
    if aud_token:
        for label, path in [
            ("Аудитор заблокирован на /settings/",        f"/logger/settings/?t={aud_token}"),
            ("Аудитор заблокирован на /encrypted-logs/",  f"/logger/encrypted-logs/?t={aud_token}"),
        ]:
            c, _, _ = http_get(path)
            ok = c in (302, 403)
            results.append((label, ok))
            row(label, f"HTTP {c}", "ok" if ok else "fail")
        # Аудитор может читать дашборд
        c_dash, _, _ = http_get(f"/logger/?t={aud_token}")
        ok_d = (c_dash == 200)
        results.append(("Аудитор читает дашборд", ok_d))
        row("Аудитор может читать дашборд", f"HTTP {c_dash}", "ok" if ok_d else "fail")
    else:
        row("Аудитор (пользователь не найден в БД)", "пропущено", "warn")

    # 2.6 Функциональная корректность: сохранение policy.json
    print(f"\n  [ Функциональная корректность — настройки политики ]")
    policy_path = Path("logger_app/migrations/policy.json")
    before_val = json.loads(policy_path.read_text(encoding="utf-8"))["base_frequency_per_second"]

    new_val = 7
    c_save, hdrs_save, t_save = http_post(
        f"/logger/settings/?t={token}",
        {"t": token, "base_frequency": new_val,
         "minor_overhead": 25, "block_seconds": 90}
    )
    after_val = json.loads(policy_path.read_text(encoding="utf-8"))["base_frequency_per_second"]
    save_ok = (c_save in (301, 302)) and (after_val == new_val)
    results.append(("Сохранение policy.json", save_ok))
    row("POST настроек → policy.json обновлён",
        f"{'ДА' if save_ok else 'НЕТ'}  {t_save*1000:.0f}ms",
        "ok" if save_ok else "fail")

    # Восстанавливаем исходное значение
    http_post(
        f"/logger/settings/?t={token}",
        {"t": token, "base_frequency": before_val,
         "minor_overhead": 20, "block_seconds": 100}
    )

    # 2.7 Шифрование
    print(f"\n  [ Шифрование данных — Fernet round-trip ]")
    try:
        os.environ.setdefault("DJANGO_SETTINGS_MODULE", "django_project.settings")
        import django; django.setup()
        from logger_app.encryption import encrypt_log, decrypt_log
        sample = "Пользователь Инженер | vm=RMS | action=write | 2026-05-22"
        t0  = time.time()
        enc = encrypt_log(sample)
        dec = decrypt_log(enc)
        enc_time   = (time.time() - t0) * 1000
        enc_ok     = (dec == sample)
        enc_hidden = (sample not in enc and "admin" not in enc)
        results.append(("Шифрование round-trip корректно", enc_ok))
        results.append(("Данные скрыты в шифртексте",      enc_hidden))
        row("Encrypt → Decrypt round-trip",
            f"{'OK' if enc_ok else 'FAIL'}  {enc_time:.2f}ms",
            "ok" if enc_ok else "fail")
        row("Открытые данные не видны в шифртексте",
            "ДА" if enc_hidden else "НЕТ", "ok" if enc_hidden else "fail")
        # Тест HMAC: подделанный шифртекст должен вызвать ошибку
        tampered_raises = False
        try:
            decrypt_log(enc[:-4] + "XXXX")
        except Exception:
            tampered_raises = True
        results.append(("HMAC: подделка вызывает ошибку", tampered_raises))
        row("HMAC: изменение шифртекста → исключение",
            "ДА" if tampered_raises else "НЕТ",
            "ok" if tampered_raises else "fail")
    except Exception as e:
        row(f"Шифрование (ошибка инициализации: {e})", "", "warn")

    # Итог
    sep()
    passed = sum(1 for _, v in results if v)
    total  = len(results)
    pct    = round(passed / total * 100) if total else 0
    row(f"Пройдено проверок: {passed}/{total}",
        "", "ok" if pct >= 80 else ("warn" if pct >= 60 else "fail"))
    row("► ОЦЕНКА ВНЕШНЕГО КАЧЕСТВА",
        f"{pct}/100",
        "ok" if pct >= 80 else ("warn" if pct >= 60 else "fail"))
    return pct


# ═══════════════════════════════════════════════════════════════════
# 3. КАЧЕСТВО ПРИ ИСПОЛЬЗОВАНИИ — сценарии пользователей
# ═══════════════════════════════════════════════════════════════════

def quality_in_use():
    hdr("3. КАЧЕСТВО ПРИ ИСПОЛЬЗОВАНИИ — сценарии пользователей")
    results = []

    # 3.1 Результативность: сценарий «Администратор просматривает дашборд»
    print("\n  [ Результативность: завершённость сценариев ]")

    c1, b1, t1 = http_get("/logger/login/")
    s1 = (c1 == 200 and b'name="password"' in b1)
    row("Шаг 1: страница входа загружена",
        f"{'OK' if s1 else 'FAIL'}  {t1*1000:.0f}ms",
        "ok" if s1 else "fail")

    token = get_auth_token()
    s2 = token is not None
    row("Шаг 2: вход в систему, токен получен",
        "OK" if s2 else "FAIL", "ok" if s2 else "fail")

    if not s2:
        row("Остальные шаги недоступны без токена", "", "fail")
        return 0

    c3, b3, t3 = http_get(f"/logger/?t={token}")
    s3 = (c3 == 200)
    row("Шаг 3: дашборд открыт",
        f"{'OK' if s3 else 'FAIL'}  {t3*1000:.0f}ms",
        "ok" if s3 else "fail")

    c4, b4, t4 = http_get(f"/logger/events/?t={token}")
    s4 = (c4 == 200)
    row("Шаг 4: журнал событий открыт",
        f"{'OK' if s4 else 'FAIL'}  {t4*1000:.0f}ms",
        "ok" if s4 else "fail")

    c5, _, t5 = http_post(
        f"/logger/settings/?t={token}",
        {"t": token, "base_frequency": 3,
         "minor_overhead": 20, "block_seconds": 100}
    )
    s5 = c5 in (301, 302)
    row("Шаг 5: настройки изменены и сохранены",
        f"{'OK' if s5 else 'FAIL'}  {t5*1000:.0f}ms",
        "ok" if s5 else "fail")

    done = sum([s1, s2, s3, s4, s5])
    pct_done = round(done / 5 * 100)
    results.append(("Завершённость основного сценария", pct_done == 100))
    sep()
    row("Завершённость сценария",
        f"{done}/5 шагов ({pct_done}%)",
        "ok" if pct_done == 100 else ("warn" if pct_done >= 80 else "fail"))

    # 3.2 Производительность: нагрузочный мини-тест дашборда
    print(f"\n  [ Производительность: 5 последовательных запросов к дашборду ]")
    times_dash = []
    for _ in range(5):
        _, _, t = http_get(f"/logger/?t={token}")
        times_dash.append(t * 1000)

    avg_t = sum(times_dash) / len(times_dash)
    max_t = max(times_dash)
    std_t = math.sqrt(sum((x - avg_t)**2 for x in times_dash) / len(times_dash))
    cv    = round(std_t / avg_t * 100) if avg_t > 0 else 0

    vals = "  ".join(f"{int(t):>5}ms" for t in times_dash)
    print(f"  Запросы:  {vals}")
    sep()
    row("Среднее время дашборда",
        f"{avg_t:.0f}ms",
        "ok" if avg_t < 800 else ("warn" if avg_t < 2000 else "fail"))
    row("Максимальное время",
        f"{max_t:.0f}ms",
        "ok" if max_t < 1500 else ("warn" if max_t < 3000 else "fail"))
    row("Коэффициент вариации (стабильность)",
        f"{cv}%",
        "ok" if cv < 30 else ("warn" if cv < 60 else "fail"))
    results.append(("Производительность", avg_t < 2000))
    results.append(("Стабильность отклика", cv < 60))

    # 3.3 Свобода от риска: обработка ошибочных действий
    print(f"\n  [ Свобода от риска: обработка ошибочных действий ]")

    # Неверный пароль
    c_bad, _, _, _ = _raw_request(
        "POST", "/logger/login/",
        body=urllib.parse.urlencode(
            {"username": "admin", "password": "неверный_пароль"}
        ).encode(),
        headers={"Content-Type": "application/x-www-form-urlencoded"}
    )
    bad_ok = (c_bad == 200)   # остаётся на форме, не редиректит
    results.append(("Неверный пароль → остаётся на форме", bad_ok))
    row("Неверный пароль → остаётся на форме входа",
        f"HTTP {c_bad}", "ok" if bad_ok else "fail")

    # Несуществующий URL
    c404, _, _ = http_get("/logger/nonexistent_page_xyz/")
    results.append(("Несуществующий URL → нет 500", c404 != 500))
    row("Несуществующий URL → нет 500",
        f"HTTP {c404}", "ok" if c404 != 500 else "fail")

    # Некорректный ввод в настройки (строка вместо числа)
    c_inv, _, _ = http_post(
        f"/logger/settings/?t={token}",
        {"t": token, "base_frequency": "abc",
         "minor_overhead": 20, "block_seconds": 100}
    )
    inv_ok = (c_inv != 500)
    results.append(("Некорректный ввод → нет 500", inv_ok))
    row("Некорректный ввод в settings → нет 500",
        f"HTTP {c_inv}", "ok" if inv_ok else "fail")

    # 3.4 Удовлетворённость: ключевые элементы UI
    print(f"\n  [ Удовлетворённость: ключевые элементы интерфейса ]")
    c_d, body_d, _ = http_get(f"/logger/?t={token}")
    ui_items = [
        ("Карточки статистики (stat-card)",      b"stat-card"     in body_d),
        ("График динамики (timelineChart)",       b"timelineChart" in body_d),
        ("Круговая диаграмма (pieChart)",         b"pieChart"      in body_d),
        ("Навигационное меню (nav-link)",         b"nav-link"      in body_d),
        ("Секция аномалий на дашборде",           "аномал".encode() in body_d),
    ]
    for label, ok in ui_items:
        results.append((label, ok))
        row(label, "ДА" if ok else "НЕТ", "ok" if ok else "warn")

    # Итог
    sep()
    passed = sum(1 for _, v in results if v)
    total  = len(results)
    pct    = round(passed / total * 100) if total else 0
    row(f"Пройдено проверок: {passed}/{total}",
        "", "ok" if pct >= 80 else ("warn" if pct >= 60 else "fail"))
    row("► ОЦЕНКА КАЧЕСТВА ПРИ ИСПОЛЬЗОВАНИИ",
        f"{pct}/100",
        "ok" if pct >= 80 else ("warn" if pct >= 60 else "fail"))
    return pct


# ═══════════════════════════════════════════════════════════════════
# 4. АВТОТЕСТЫ pytest
# ═══════════════════════════════════════════════════════════════════

def run_pytest():
    hdr("4. АВТОТЕСТЫ — pytest (tests/)")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-v",
         "--tb=short", "--no-header", "-q"],
        capture_output=True, text=True
    )
    for line in result.stdout.splitlines():
        print(f"  {line}")
    if result.returncode != 0 and result.stderr:
        for line in result.stderr.splitlines()[:8]:
            if line.strip():
                print(f"  {line}")

    passed = failed = errors = 0
    for line in result.stdout.splitlines():
        parts = line.split()
        for i, p in enumerate(parts):
            if i > 0:
                try:
                    n = int(parts[i - 1])
                    if p == "passed":  passed = n
                    if p == "failed":  failed = n
                    if p == "error":   errors = n
                except ValueError:
                    pass

    total = passed + failed + errors
    pct   = round(passed / total * 100) if total > 0 else 0
    sep()
    row("Пройдено тестов",
        f"{passed}/{total}  ({pct}%)",
        "ok" if pct == 100 else ("warn" if pct >= 80 else "fail"))
    return pct


# ═══════════════════════════════════════════════════════════════════
# 5. ПАРАЛЛЕЛЬНАЯ НАГРУЗКА — имитация одновременных пользователей
# ═══════════════════════════════════════════════════════════════════

def load_test():
    hdr("5. НАГРУЗОЧНЫЙ ТЕСТ — параллельные запросы (threading)")

    print("""
  Цель: показать реальное поведение single-worker Gunicorn
  при одновременных обращениях нескольких «пользователей».
  Ожидаемый эффект: при N > 1 потоке запросы выстраиваются
  в очередь → время отклика растёт линейно (1 worker = 1 CPU).
""")

    # Получаем токен один раз для всех потоков
    token = get_auth_token()
    if not token:
        row("Нет токена — нагрузочный тест пропущен", "", "fail")
        return 0

    path = f"/logger/?t={token}"

    def worker(idx, results_list):
        """Один поток = один виртуальный пользователь."""
        code, _, elapsed = http_get(path)
        results_list[idx] = {"code": code, "ms": elapsed * 1000}

    scenarios = [
        (1,  "Базовый сценарий: 1 пользователь"),
        (3,  "Лёгкая нагрузка:  3 одновременных"),
        (6,  "Средняя нагрузка: 6 одновременных"),
        (10, "Пиковая нагрузка: 10 одновременных"),
    ]

    print(f"  {'Сценарий':<38} {'Среднее':>8} {'Макс':>7} {'Мин':>7} "
          f"{'Успех':>7} {'Статус'}")
    print(f"  {'─'*38} {'─'*8} {'─'*7} {'─'*7} {'─'*7} {'─'*8}")

    load_scores = []
    baseline_avg = None

    for n_users, label in scenarios:
        slot = [None] * n_users
        threads = [threading.Thread(target=worker, args=(i, slot))
                   for i in range(n_users)]

        # Запускаем все потоки одновременно
        for t in threads: t.start()
        for t in threads: t.join()

        times   = [r["ms"] for r in slot if r]
        codes   = [r["code"] for r in slot if r]
        ok_cnt  = sum(1 for c in codes if c == 200)
        avg_t   = sum(times) / len(times) if times else 0
        max_t   = max(times) if times else 0
        min_t   = min(times) if times else 0
        success = round(ok_cnt / n_users * 100)

        if baseline_avg is None:
            baseline_avg = avg_t

        # Деградация: насколько вырос средний отклик относительно baseline
        degradation = round((avg_t - baseline_avg) / baseline_avg * 100) if baseline_avg else 0

        status = (
            "ok"   if avg_t < 800  and success == 100 else
            "warn" if avg_t < 2500 and success >= 80  else
            "fail"
        )
        deg_str = f"(+{degradation}%)" if degradation > 0 else "(база)"

        icons = {"ok": "✅", "warn": "⚠️ ", "fail": "❌"}
        print(f"  {icons[status]} {label:<36} {avg_t:>6.0f}ms "
              f"{max_t:>5.0f}ms {min_t:>5.0f}ms {success:>5}%  {deg_str}")

        load_scores.append((n_users, avg_t, success, status))

    sep()

    # Итоговый балл: штрафуем за деградацию при 10 пользователях
    avg_10  = next((a for n, a, s, _ in load_scores if n == 10), 9999)
    succ_10 = next((s for n, a, s, _ in load_scores if n == 10), 0)

    if avg_10 < 800 and succ_10 == 100:
        score = 100
        verdict = "отличная масштабируемость"
    elif avg_10 < 2000 and succ_10 >= 90:
        score = 72
        verdict = "приемлемо — очередь запросов ожидаема для 1 worker"
    elif avg_10 < 5000 and succ_10 >= 70:
        score = 50
        verdict = "значительная деградация — рекомендуется увеличить workers"
    else:
        score = 25
        verdict = "критическая деградация или отказы под нагрузкой"

    row("Масштабируемость (10 пользователей)",
        f"{avg_10:.0f}ms, {succ_10}% успех", load_scores[-1][3])
    row("► ОЦЕНКА ПОД НАГРУЗКОЙ",
        f"{score}/100  — {verdict}",
        "ok" if score >= 80 else ("warn" if score >= 50 else "fail"))

    # Пояснение для отчёта
    print(f"""
  Пояснение к результатам:
  Single-worker Gunicorn обрабатывает запросы строго последовательно.
  При N одновременных запросах N-1 из них ждут в очереди, поэтому
  время отклика при пиковой нагрузке = среднее_время × N_пользователей.
  Для устранения: увеличить workers в gunicorn.conf.py (workers = 4)
  или добавить кэширование результатов simulate_events().
""")

    return score


# ═══════════════════════════════════════════════════════════════════
# СВОДНЫЙ ОТЧЁТ
# ═══════════════════════════════════════════════════════════════════

def summary(s_internal, s_external, s_use, s_tests, s_load):
    hdr("СВОДНЫЙ ОТЧЁТ ПО КАЧЕСТВУ — ГОСТ Р ИСО/МЭК 25010")

    print(f"\n  {'Раздел':<46} {'Оценка':>7}   {'Диаграмма'}")
    print(f"  {'─'*46} {'─'*7}   {'─'*12}")

    rows_data = [
        ("1. Внутреннее качество (статический анализ)",   s_internal, 0.15),
        ("2. Внешнее качество (функц. и HTTP-тесты)",     s_external, 0.30),
        ("3. Качество при использовании (сценарии)",      s_use,      0.20),
        ("4. Автотесты pytest",                           s_tests,    0.20),
        ("5. Нагрузочный тест (масштабируемость)",        s_load,     0.15),
    ]
    total_score = 0
    for label, score, weight in rows_data:
        icon  = "✅" if score >= 80 else ("⚠️ " if score >= 60 else "❌")
        bar   = "█" * (score // 10) + "░" * (10 - score // 10)
        print(f"  {icon} {label:<44} {score:>4}/100   {bar}")
        total_score += score * weight

    total_score = round(total_score)
    level = (
        "ВЫСОКОЕ"            if total_score >= 80 else
        "ПРИЕМЛЕМОЕ"         if total_score >= 65 else
        "ТРЕБУЕТ УЛУЧШЕНИЯ"  if total_score >= 50 else
        "НИЗКОЕ"
    )
    icon = "✅" if total_score >= 80 else ("⚠️ " if total_score >= 65 else "❌")
    bar  = "█" * (total_score // 10) + "░" * (10 - total_score // 10)
    sep()
    print(f"\n  {icon}  ИТОГОВАЯ ОЦЕНКА КАЧЕСТВА: {total_score}/100  [{level}]")
    print(f"      {bar}")

    print(f"\n  Рекомендации по улучшению:")
    if s_internal < 70:
        print("  • Увеличить плотность комментариев (цель: ≥ 10%)")
        print("  • Добавить докстринги к функциям в views.py, models.py")
    if s_external < 85:
        print("  • Добавить явную обработку некорректного ввода в settings_view")
    if s_use < 80:
        print("  • Рассмотреть кэширование для повышения стабильности отклика")
    if s_tests < 100:
        print("  • Дополнить тестовое покрытие (settings_view, logout, events)")
    if s_load < 80:
        print("  • Масштабируемость: увеличить workers = 4 в gunicorn.conf.py")
        print("  • Добавить кэш для generate_events() (например, functools.lru_cache)")
    if total_score >= 65:
        print("  • Интегрировать Prometheus для непрерывного мониторинга качества")

    print(f"\n  Дата проверки : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"  Программное средство : Security Logger (Django 5.0.2, Python 3.10)")
    print(f"  Стандарт : ГОСТ Р ИСО/МЭК 25010-2015\n")


# ═══════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    print(f"\n{SEP2}")
    print("  Измерение качества ПО — ГОСТ Р ИСО/МЭК 25010")
    print(f"  Security Logger | {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(SEP2)

    s1 = internal_quality()
    s2 = external_quality()
    s3 = quality_in_use()
    s4 = run_pytest()
    s5 = load_test()
    summary(s1, s2, s3, s4, s5)
