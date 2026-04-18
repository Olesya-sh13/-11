"""
Модуль расчёта событий безопасности.
Генерирует имитированные события доступа, применяет политики,
детектирует аномалии и возвращает статистику.
"""

import json
import math
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

# Загрузка конфигурации из JSON-файла
CONFIG_PATH = Path(__file__).parent.parent / "migrations" / "policy.json"

def load_config():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)

# Глобальные параметры (загружаются один раз при импорте)
_config = load_config()
BASE_FREQ = _config["base_frequency_per_second"]
MINOR_OVERHEAD_PERCENT = _config["minor_overhead_percent"]
CRITICAL_THRESHOLD = math.ceil(BASE_FREQ * (1 + MINOR_OVERHEAD_PERCENT / 100))
TEMP_BLOCK_SEC = _config["temporary_block_seconds"]
USERS = _config["users"]
VMS = _config["vms"]
POLICY = _config["policy"]

def check_policy(user, vm, action):
    """
    Проверка доступа по политике.
    Возвращает (allowed, reason)
    - allowed: True/False
    - reason: пояснение на русском
    """
    rights = POLICY.get(user, {}).get(vm)
    if rights is None:
        return False, "Нет доступа к этим данным"
    if action == 'read' and rights in ('read', 'readwrite'):
        return True, "Разрешено чтение"
    if action == 'write' and rights == 'readwrite':
        return True, "Разрешена запись"
    return False, f"Операция '{action}' не разрешена"

def generate_events():
    """
    Генерирует DataFrame со всеми событиями.
    Содержит 5 типов событий:
    1. Злоумышленник (5 попыток) — всегда запрещён
    2. Нарушения политики (3 случая)
    3. Небольшое превышение частоты (4 запроса от Геолога)
    4. Критическое превышение частоты (25 запросов от Инженера)
    5. Нормальные разрешённые запросы (100 штук)
    """
    start_time = datetime.now() - timedelta(minutes=5)
    events = []

    # 1. Злоумышленник (5 попыток)
    for i in range(5):
        timestamp = start_time + timedelta(seconds=random.randint(0, 300))
        vm = random.choice(VMS)
        action = random.choice(['read', 'write'])
        events.append({
            'timestamp': timestamp,
            'user': 'Злоумышленник',
            'vm': vm,
            'action': action,
            'policy_allowed': False,
            'policy_reason': "Пользователь не найден в системе"
        })

    # 2. Нарушения политики (3 случая)
    events.append({
        'timestamp': start_time + timedelta(seconds=random.randint(30, 90)),
        'user': 'Оператор',
        'vm': 'Телеметрия скважин (OpsLink)',
        'action': 'write',
        'policy_allowed': False,
        'policy_reason': "Оператор имеет право только на чтение телеметрии"
    })
    events.append({
        'timestamp': start_time + timedelta(seconds=random.randint(100, 150)),
        'user': 'Геолог',
        'vm': 'Корпоративная БД (Epos)',
        'action': 'read',
        'policy_allowed': False,
        'policy_reason': "Геолог не имеет права доступа к БД"
    })
    events.append({
        'timestamp': start_time + timedelta(seconds=random.randint(160, 200)),
        'user': 'Аудитор',
        'vm': 'Геологическая модель (RMS)',
        'action': 'write',
        'policy_allowed': False,
        'policy_reason': "Аудитор имеет право только на чтение"
    })

    # 3. Небольшое превышение частоты (4 запроса от Геолога за 1 секунду)
    small_attack_time = start_time + timedelta(seconds=220)
    for i in range(4):
        timestamp = small_attack_time + timedelta(milliseconds=random.randint(0, 1000))
        vm = random.choice(['Геологическая модель (RMS)', 'Симуляция резервуара (Tempest)'])
        action = random.choice(['read', 'write'])
        allowed, reason = check_policy('Геолог', vm, action)
        events.append({
            'timestamp': timestamp,
            'user': 'Геолог',
            'vm': vm,
            'action': action,
            'policy_allowed': allowed,
            'policy_reason': reason
        })

    # 4. Критическое превышение частоты (25 запросов от Инженера за 1 секунду)
    attack_time = start_time + timedelta(seconds=260)
    for i in range(25):
        timestamp = attack_time + timedelta(milliseconds=random.randint(0, 1000))
        vm = random.choice(['Геологическая модель (RMS)', 'Симуляция резервуара (Tempest)'])
        action = random.choice(['read', 'write'])
        allowed, reason = check_policy('Инженер-разработчик', vm, action)
        events.append({
            'timestamp': timestamp,
            'user': 'Инженер-разработчик',
            'vm': vm,
            'action': action,
            'policy_allowed': allowed,
            'policy_reason': reason
        })

    # 5. Нормальные разрешённые запросы (100 штук)
    for i in range(100):
        timestamp = start_time + timedelta(seconds=random.randint(0, 300))
        user = random.choice(USERS)
        # Выбираем VM, к которой у пользователя есть доступ (не None)
        available_vms = [vm for vm in VMS if POLICY.get(user, {}).get(vm) is not None]
        if not available_vms:
            available_vms = VMS
        vm = random.choice(available_vms)
        rights = POLICY.get(user, {}).get(vm)
        if rights == 'readwrite':
            action = random.choice(['read', 'write'])
        else:
            action = 'read'
        allowed, reason = check_policy(user, vm, action)
        events.append({
            'timestamp': timestamp,
            'user': user,
            'vm': vm,
            'action': action,
            'policy_allowed': allowed,
            'policy_reason': reason
        })

    # Сортируем по времени
    events.sort(key=lambda x: x['timestamp'])
    df = pd.DataFrame(events)

    # --- Детекция аномальной частоты и принятие решения ---
    df['is_frequency_anomaly'] = False
    df['requests_per_second'] = 0
    df['is_critical_anomaly'] = False
    df['final_allowed'] = df['policy_allowed']
    df['final_reason'] = df['policy_reason']

    blocked_users_vm = {}  # Словарь для временных блокировок

    for idx, row in df.iterrows():
        t = row['timestamp']
        user = row['user']
        vm = row['vm']

        # Злоумышленника не блокируем (у него отдельная статистика)
        if user == 'Злоумышленник':
            continue

        key = (user, vm)

        # Проверка временной блокировки
        if key in blocked_users_vm and t < blocked_users_vm[key]:
            df.at[idx, 'final_allowed'] = False
            df.at[idx, 'final_reason'] = f"Временная блокировка (до {blocked_users_vm[key].strftime('%H:%M:%S')})"
            df.at[idx, 'is_frequency_anomaly'] = True
            df.at[idx, 'is_critical_anomaly'] = True
            continue

        # Подсчёт запросов за последнюю секунду
        mask = (df['timestamp'] >= t - timedelta(seconds=1)) & (df['timestamp'] <= t) & (df['user'] == user) & (df['vm'] == vm)
        count = mask.sum()
        df.at[idx, 'requests_per_second'] = count

        # Если превышение частоты
        if count > BASE_FREQ:
            is_critical = count > CRITICAL_THRESHOLD
            df.at[idx, 'final_allowed'] = False
            df.at[idx, 'is_frequency_anomaly'] = True
            df.at[idx, 'is_critical_anomaly'] = is_critical
            if is_critical:
                df.at[idx, 'final_reason'] = f"Критическое превышение частоты ({count} > {CRITICAL_THRESHOLD:.0f} запросов/сек)"
                blocked_users_vm[key] = t + timedelta(seconds=TEMP_BLOCK_SEC)
            else:
                df.at[idx, 'final_reason'] = f"Превышение частоты ({count} запросов/сек)"

    # Защита от пустых значений
    df['final_reason'] = df['final_reason'].fillna('Доступ запрещён политикой безопасности')

    return df

def run_security_simulation():
    """
    Выполняет полное моделирование и возвращает словарь со статистикой
    и данными для веб-интерфейса.
    """
    df = generate_events()

    total_events = len(df)
    final_allowed = df['final_allowed'].sum()
    final_denied = total_events - final_allowed
    anomaly_events = df['is_frequency_anomaly'].sum()
    critical_anomaly_events = df['is_critical_anomaly'].sum()

    # Статистика по легитимным пользователям
    df_legit = df[df['user'] != 'Злоумышленник']
    user_stats = df_legit.groupby(['user', 'final_allowed']).size().unstack(fill_value=0)
    user_stats.columns = ['Запрещено', 'Разрешено']
    user_stats['Всего'] = user_stats['Запрещено'] + user_stats['Разрешено']
    user_stats = user_stats[['Разрешено', 'Запрещено', 'Всего']]
    user_stats.index.name = 'Пользователь'

    critical_by_user = df_legit[df_legit['is_critical_anomaly']].groupby('user').size()
    user_stats['Критических аномалий'] = critical_by_user.reindex(user_stats.index, fill_value=0)

    # Статистика по виртуальным машинам
    vm_stats = df_legit.groupby(['vm', 'final_allowed']).size().unstack(fill_value=0)
    vm_stats.columns = ['Запрещено', 'Разрешено']
    vm_stats['Всего'] = vm_stats['Запрещено'] + vm_stats['Разрешено']
    vm_stats = vm_stats[['Разрешено', 'Запрещено', 'Всего']]
    vm_stats.index.name = 'Виртуальная машина'

    # Данные для круговой диаграммы
    pie_data = {'Разрешено': final_allowed, 'Запрещено': final_denied}

    # Данные для временного графика
    df_time = df_legit.copy()
    if not df_time.empty:
        df_time['time_sec'] = df_time['timestamp'].dt.floor('s')
        timeline_allowed = df_time[df_time['final_allowed'] == True].groupby('time_sec').size()
        timeline_denied = df_time[df_time['final_allowed'] == False].groupby('time_sec').size()

        # Преобразуем индексы в строки для JSON
        timeline = {
            'allowed': {'times': [str(t) for t in timeline_allowed.index.tolist()], 'values': timeline_allowed.values.tolist()},
            'denied': {'times': [str(t) for t in timeline_denied.index.tolist()], 'values': timeline_denied.values.tolist()}
        }
    else:
        timeline = {'allowed': {'times': [], 'values': []}, 'denied': {'times': [], 'values': []}}

    # Злоумышленник
    attacker_events = df[df['user'] == 'Злоумышленник']
    attacker_count = len(attacker_events)
    attacker_by_vm = attacker_events.groupby('vm').size().to_dict()

    # Преобразование таблиц в HTML с русскими заголовками
    user_stats_html = user_stats.to_html(classes='table', border=0)
    vm_stats_html = vm_stats.to_html(classes='table', border=0)

    return {
        'total_events': total_events,
        'final_allowed': final_allowed,
        'final_denied': final_denied,
        'anomaly_events': anomaly_events,
        'critical_anomaly_events': critical_anomaly_events,
        'user_stats': user_stats_html,
        'vm_stats': vm_stats_html,
        'pie_data': pie_data,
        'timeline': timeline,
        'attacker_count': attacker_count,
        'attacker_by_vm': attacker_by_vm,
    }