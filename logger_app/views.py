"""
Представления (контроллеры) для отображения страниц.
Содержит логику аутентификации и разграничения прав доступа.
"""

import json
from pathlib import Path
from datetime import datetime
from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required, user_passes_test
from django.core.paginator import Paginator
from django.contrib.auth import logout as auth_logout
from django.contrib.auth import authenticate, login as auth_login
from django.views.decorators.csrf import csrf_exempt
from .data.utils import run_security_simulation, generate_events



@csrf_exempt
def custom_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            auth_login(request, user)
            return redirect('logger_app:dashboard')
        else:
            return render(request, 'logger_app/login.html', {'error': 'Неверное имя пользователя или пароль'})
    else:
        return render(request, 'logger_app/login.html')


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def is_admin(user):
    """Проверка, является ли пользователь администратором"""
    return user.role == 'admin' or user.is_superuser


# ==================== ПРЕДСТАВЛЕНИЯ ====================

@login_required(login_url='/logger/login/')
def log_dashboard(request):
    """Дашборд — полная статистика для всех авторизованных пользователей"""
    data = run_security_simulation()
    user = request.user

    data['user_role'] = user.get_role_display()
    data['is_admin'] = is_admin(user)
    data['username'] = user.username

    return render(request, 'logger_app/dashboard.html', data)


@login_required(login_url='/logger/login/')
def event_log(request):
    """Журнал событий — все события для всех авторизованных пользователей"""
    df = generate_events()
    events = df.to_dict('records')

    # Фильтрация (доступна всем)
    user_filter = request.GET.get('user', '')
    vm_filter = request.GET.get('vm', '')
    result_filter = request.GET.get('result', '')

    if user_filter:
        events = [e for e in events if e['user'] == user_filter]
    if vm_filter:
        events = [e for e in events if e['vm'] == vm_filter]
    if result_filter:
        allowed = (result_filter == 'allowed')
        events = [e for e in events if e['final_allowed'] == allowed]

    # Пагинация (20 записей на страницу)
    paginator = Paginator(events, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    all_users = sorted(set(e['user'] for e in events))
    all_vms = sorted(set(e['vm'] for e in events))

    context = {
        'page_obj': page_obj,
        'all_users': all_users,
        'all_vms': all_vms,
        'selected_user': user_filter,
        'selected_vm': vm_filter,
        'selected_result': result_filter,
        'user_role': request.user.get_role_display(),
        'is_admin': is_admin(request.user),
        'username': request.user.username,
    }
    return render(request, 'logger_app/event_log.html', context)


@login_required(login_url='/logger/login/')
@user_passes_test(is_admin, login_url='/logger/')
def view_encrypted_logs(request):
    """Просмотр зашифрованных логов — ТОЛЬКО ДЛЯ АДМИНИСТРАТОРА"""
    from .encryption import encrypt_log, decrypt_log

    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)

    # Если зашифрованных файлов нет — генерируем их из текущей симуляции
    if not list(log_dir.glob("*.enc")):
        df = generate_events()
        now_str = datetime.now().strftime('%Y%m%d_%H%M%S')

        # Лог 1: события злоумышленника
        attacker_df = df[df['user'] == 'Злоумышленник']
        attacker_records = []
        for _, row in attacker_df.iterrows():
            attacker_records.append({
                'timestamp': str(row['timestamp']),
                'user': row['user'],
                'vm': row['vm'],
                'action': row['action'],
                'result': 'ЗАПРЕЩЕНО',
                'reason': row['final_reason'],
            })
        log1 = json.dumps({'type': 'attacker_events', 'generated': str(datetime.now()), 'events': attacker_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'attacker_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log1))

        # Лог 2: нарушения политики (легитимные пользователи, запрещённые по политике)
        denied_df = df[(df['user'] != 'Злоумышленник') & (df['policy_allowed'] == False)]
        denied_records = []
        for _, row in denied_df.iterrows():
            denied_records.append({
                'timestamp': str(row['timestamp']),
                'user': row['user'],
                'vm': row['vm'],
                'action': row['action'],
                'result': 'ЗАПРЕЩЕНО',
                'reason': row['policy_reason'],
            })
        log2 = json.dumps({'type': 'policy_violations', 'generated': str(datetime.now()), 'events': denied_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'policy_violations_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log2))

        # Лог 3: аномалии частоты
        anomaly_df = df[df['is_critical_anomaly'] == True]
        anomaly_records = []
        for _, row in anomaly_df.iterrows():
            anomaly_records.append({
                'timestamp': str(row['timestamp']),
                'user': row['user'],
                'vm': row['vm'],
                'action': row['action'],
                'requests_per_second': int(row['requests_per_second']),
                'result': 'ЗАБЛОКИРОВАНО',
                'reason': row['final_reason'],
            })
        log3 = json.dumps({'type': 'frequency_anomalies', 'generated': str(datetime.now()), 'events': anomaly_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'anomalies_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log3))

    # Собираем список файлов
    encrypted_files = list(log_dir.glob("*.enc"))
    files_info = []
    type_labels = {
        'attacker': 'События злоумышленника',
        'policy_violations': 'Нарушения политики',
        'anomalies': 'Аномалии частоты',
    }
    for f in encrypted_files:
        stem = f.stem
        label = f.name
        for key, rus in type_labels.items():
            if stem.startswith(key):
                label = rus
                break
        files_info.append({
            'name': f.name,
            'label': label,
            'size': f.stat().st_size,
            'modified': datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S'),
        })
    files_info.sort(key=lambda x: x['modified'], reverse=True)

    # Расшифровка выбранного файла
    file_to_view = request.GET.get('view')
    decrypted_content = None
    decrypted_error = None

    if file_to_view:
        file_path = log_dir / file_to_view
        if file_path.exists():
            with open(file_path, 'r', encoding='utf-8') as f:
                encrypted_content = f.read()
            try:
                raw = decrypt_log(encrypted_content)
                decrypted_content = json.loads(raw)
            except Exception as e:
                decrypted_error = f"Ошибка расшифровки: {e}"

    context = {
        'files': files_info,
        'decrypted_content': decrypted_content,
        'decrypted_error': decrypted_error,
        'viewed_file': file_to_view,
        'username': request.user.username,
        'is_admin': True,
    }
    return render(request, 'logger_app/encrypted_logs.html', context)


@login_required(login_url='/logger/login/')
@user_passes_test(is_admin, login_url='/logger/')
def settings_view(request):
    """Страница настроек (только для администратора)"""
    policy_path = Path(__file__).parent / "migrations" / "policy.json"

    if request.method == 'POST':
        # Получаем новые значения из формы
        new_freq = int(request.POST.get('base_frequency', 2))
        new_percent = int(request.POST.get('minor_overhead', 20))
        new_block_sec = int(request.POST.get('block_seconds', 100))

        # Загружаем текущую политику
        with open(policy_path, 'r', encoding='utf-8') as f:
            policy = json.load(f)

        # Обновляем параметры
        policy['base_frequency_per_second'] = new_freq
        policy['minor_overhead_percent'] = new_percent
        policy['temporary_block_seconds'] = new_block_sec

        # Сохраняем обратно
        with open(policy_path, 'w', encoding='utf-8') as f:
            json.dump(policy, f, ensure_ascii=False, indent=2)

        # Логируем изменение
        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        with open(log_dir / "audit.log", 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} | Admin {request.user.username} | Changed params: freq={new_freq}, overhead={new_percent}, block_sec={new_block_sec}\n")

        return redirect('logger_app:settings')

    # GET — показываем форму с текущими значениями
    with open(policy_path, 'r', encoding='utf-8') as f:
        policy = json.load(f)

    context = {
        'base_freq': policy.get('base_frequency_per_second', 2),
        'minor_overhead': policy.get('minor_overhead_percent', 20),
        'block_sec': policy.get('temporary_block_seconds', 100),
    }
    return render(request, 'logger_app/settings.html', context)


def logout_view(request):
    auth_logout(request)
    return redirect('/logger/login/')