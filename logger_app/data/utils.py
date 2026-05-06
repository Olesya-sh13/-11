"""
Модуль расчёта событий безопасности.
Генерирует имитированные события доступа, применяет политики,
детектирует аномалии и возвращает статистику.
Параметры читаются из policy.json при каждом вызове — отражают текущие настройки.
"""
# Принято Петровым В.П.
import json
import math
import random
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from pathlib import Path

CONFIG_PATH = Path(__file__).parent.parent / "migrations" / "policy.json"


def load_config():
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        return json.load(f)


def check_policy(user, vm, action, policy):
    """
    Проверка доступа по политике.
    Возвращает (allowed, reason)
    """
    rights = policy.get(user, {}).get(vm)
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
    Параметры симуляции берутся из policy.json в момент вызова.
    """
    # Загружаем актуальные параметры каждый раз
    config = load_config()
    base_freq = config["base_frequency_per_second"]
    minor_overhead_percent = config["minor_overhead_percent"]
    critical_threshold = math.ceil(base_freq * (1 + minor_overhead_percent / 100))
    temp_block_sec = config["temporary_block_seconds"]
    users = config["users"]
    vms = config["vms"]
    policy = config["policy"]

    start_time = datetime.now() - timedelta(minutes=5)
    events = []

    # 1. Злоумышленник (5 попыток)
    for i in range(5):
        timestamp = start_time + timedelta(seconds=random.randint(0, 300))
        vm = random.choice(vms)
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

    # 3. Небольшое превышение частоты:
    # base_freq + 1 запросов от Геолога за ~1 секунду
    minor_burst = base_freq + 1
    small_attack_time = start_time + timedelta(seconds=220)
    for i in range(minor_burst):
        timestamp = small_attack_time + timedelta(milliseconds=random.randint(0, 900))
        vm = random.choice(['Геологическая модель (RMS)', 'Симуляция резервуара (Tempest)'])
        action = random.choice(['read', 'write'])
        allowed, reason = check_policy('Геолог', vm, action, policy)
        events.append({
            'timestamp': timestamp,
            'user': 'Геолог',
            'vm': vm,
            'action': action,
            'policy_allowed': allowed,
            'policy_reason': reason
        })

    # 4. Критическое превышение частоты:
    # critical_threshold * 3 запросов от Инженера за ~1 секунду — гарантированно критично
    critical_burst = critical_threshold * 3
    attack_time = start_time + timedelta(seconds=260)
    for i in range(critical_burst):
        timestamp = attack_time + timedelta(milliseconds=random.randint(0, 900))
        vm = random.choice(['Геологическая модель (RMS)', 'Симуляция резервуара (Tempest)'])
        action = random.choice(['read', 'write'])
        allowed, reason = check_policy('Инженер-разработчик', vm, action, policy)
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
        user = random.choice(users)
        available_vms = [vm for vm in vms if policy.get(user, {}).get(vm) is not None]
        if not available_vms:
            available_vms = vms
        vm = random.choice(available_vms)
        rights = policy.get(user, {}).get(vm)
        if rights == 'readwrite':
            action = random.choice(['read', 'write'])
        else:
            action = 'read'
        allowed, reason = check_policy(user, vm, action, policy)
        events.append({
            'timestamp': timestamp,
            'user': user,
            'vm': vm,
            'action': action,
            'policy_allowed': allowed,
            'policy_reason': reason
        })

    events.sort(key=lambda x: x['timestamp'])
    df = pd.DataFrame(events)

    # --- Детекция аномальной частоты и принятие решения ---
    df['is_frequency_anomaly'] = False
    df['requests_per_second'] = 0
    df['is_critical_anomaly'] = False
    df['final_allowed'] = df['policy_allowed']
    df['final_reason'] = df['policy_reason']

    blocked_users_vm = {}

    for idx, row in df.iterrows():
        t = row['timestamp']
        user = row['user']
        vm = row['vm']

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
        mask = (
            (df['timestamp'] >= t - timedelta(seconds=1)) &
            (df['timestamp'] <= t) &
            (df['user'] == user) &
            (df['vm'] == vm)
        )
        count = int(mask.sum())
        df.at[idx, 'requests_per_second'] = count

        # Если превышение базовой частоты
        if count > base_freq:
            is_critical = count > critical_threshold
            df.at[idx, 'final_allowed'] = False
            df.at[idx, 'is_frequency_anomaly'] = True
            df.at[idx, 'is_critical_anomaly'] = is_critical
            if is_critical:
                df.at[idx, 'final_reason'] = (
                    f"Критическое превышение частоты ({count} > {critical_threshold} запросов/сек), "
                    f"блокировка на {temp_block_sec} сек"
                )
                blocked_users_vm[key] = t + timedelta(seconds=temp_block_sec)
            else:
                df.at[idx, 'final_reason'] = (
                    f"Превышение частоты ({count} > {base_freq} запросов/сек)"
                )

    df['final_reason'] = df['final_reason'].fillna('Доступ запрещён политикой безопасности')

    return df


def run_security_simulation():
    """
    Выполняет полное моделирование и возвращает словарь со статистикой
    и данными для веб-интерфейса.
    """
    df = generate_events()

    total_events = len(df)
    final_allowed = int(df['final_allowed'].sum())
    final_denied = total_events - final_allowed
    anomaly_events = int(df['is_frequency_anomaly'].sum())
    critical_anomaly_events = int(df['is_critical_anomaly'].sum())

    df_legit = df[df['user'] != 'Злоумышленник']
    user_stats = df_legit.groupby(['user', 'final_allowed']).size().unstack(fill_value=0)

    # Гарантируем наличие обеих колонок
    for col in [False, True]:
        if col not in user_stats.columns:
            user_stats[col] = 0
    user_stats.columns = ['Запрещено', 'Разрешено']
    user_stats['Всего'] = user_stats['Запрещено'] + user_stats['Разрешено']
    user_stats = user_stats[['Разрешено', 'Запрещено', 'Всего']]
    user_stats.index.name = 'Пользователь'

    critical_by_user = df_legit[df_legit['is_critical_anomaly']].groupby('user').size()
    user_stats['Критических аномалий'] = critical_by_user.reindex(user_stats.index, fill_value=0)

    vm_stats = df_legit.groupby(['vm', 'final_allowed']).size().unstack(fill_value=0)
    for col in [False, True]:
        if col not in vm_stats.columns:
            vm_stats[col] = 0
    vm_stats.columns = ['Запрещено', 'Разрешено']
    vm_stats['Всего'] = vm_stats['Запрещено'] + vm_stats['Разрешено']
    vm_stats = vm_stats[['Разрешено', 'Запрещено', 'Всего']]
    vm_stats.index.name = 'Виртуальная машина'

    pie_data = {'Разрешено': final_allowed, 'Запрещено': final_denied}

    df_time = df_legit.copy()
    if not df_time.empty:
        df_time['time_sec'] = df_time['timestamp'].dt.floor('s')
        timeline_allowed = df_time[df_time['final_allowed'] == True].groupby('time_sec').size()
        timeline_denied = df_time[df_time['final_allowed'] == False].groupby('time_sec').size()
        timeline = {
            'allowed': {
                'times': [t.strftime('%H:%M:%S') for t in timeline_allowed.index.tolist()],
                'values': timeline_allowed.values.tolist()
            },
            'denied': {
                'times': [t.strftime('%H:%M:%S') for t in timeline_denied.index.tolist()],
                'values': timeline_denied.values.tolist()
            }
        }
    else:
        timeline = {'allowed': {'times': [], 'values': []}, 'denied': {'times': [], 'values': []}}

    attacker_events = df[df['user'] == 'Злоумышленник']
    attacker_count = len(attacker_events)
    attacker_by_vm = attacker_events.groupby('vm').size().to_dict()

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
