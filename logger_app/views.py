"""
Представления (контроллеры) для отображения страниц.
Аутентификация через URL-токены (обходит ограничения cookies в iframe).
"""

import json
import secrets
import time
from pathlib import Path
from datetime import datetime
from django.shortcuts import render, redirect
from django.core.paginator import Paginator
from django.contrib.auth import authenticate
from django.views.decorators.csrf import csrf_exempt
from .data.utils import run_security_simulation, generate_events
from .models import User


# ==================== ТОКЕН-ХРАНИЛИЩЕ ====================

_TOKEN_STORE = {}
TOKEN_TTL = 24 * 3600  # 24 часа


def _generate_token(user):
    token = secrets.token_urlsafe(32)
    _TOKEN_STORE[token] = {'user_id': user.pk, 'expires': time.time() + TOKEN_TTL}
    _cleanup_tokens()
    return token


def _get_user(token):
    if not token:
        return None
    entry = _TOKEN_STORE.get(token)
    if not entry:
        return None
    if time.time() > entry['expires']:
        _TOKEN_STORE.pop(token, None)
        return None
    try:
        return User.objects.get(pk=entry['user_id'])
    except User.DoesNotExist:
        return None


def _invalidate_token(token):
    _TOKEN_STORE.pop(token, None)


def _cleanup_tokens():
    now = time.time()
    for k in [k for k, v in list(_TOKEN_STORE.items()) if now > v['expires']]:
        del _TOKEN_STORE[k]


def _get_token(request):
    return request.GET.get('t') or request.POST.get('t') or ''


# ==================== ДЕКОРАТОРЫ ====================

def token_required(view_func):
    def wrapper(request, *args, **kwargs):
        token = _get_token(request)
        user = _get_user(token)
        if user is None:
            return redirect('/logger/login/')
        request.auth_user = user
        request.auth_token = token
        return view_func(request, *args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


def admin_required(view_func):
    def wrapper(request, *args, **kwargs):
        token = _get_token(request)
        user = _get_user(token)
        if user is None:
            return redirect('/logger/login/')
        if not _is_admin(user):
            return redirect(f'/logger/?t={token}')
        request.auth_user = user
        request.auth_token = token
        return view_func(request, *args, **kwargs)
    wrapper.__name__ = view_func.__name__
    return wrapper


# ==================== ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ====================

def _is_admin(user):
    return user.role == 'admin' or user.is_superuser


# ==================== ПРЕДСТАВЛЕНИЯ ====================

@csrf_exempt
def custom_login(request):
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')
        user = authenticate(request, username=username, password=password)
        if user is not None:
            token = _generate_token(user)
            return redirect(f'/logger/?t={token}')
        else:
            return render(request, 'logger_app/login.html', {'error': 'Неверное имя пользователя или пароль'})
    return render(request, 'logger_app/login.html')


@token_required
def log_dashboard(request):
    data = run_security_simulation()
    user = request.auth_user
    token = request.auth_token

    data['user_role'] = user.get_role_display()
    data['is_admin'] = _is_admin(user)
    data['username'] = user.username
    data['token'] = token

    return render(request, 'logger_app/dashboard.html', data)


@token_required
def event_log(request):
    df = generate_events()
    events = df.to_dict('records')
    user = request.auth_user
    token = request.auth_token

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

    paginator = Paginator(events, 20)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    all_users = sorted(set(e['user'] for e in df.to_dict('records')))
    all_vms = sorted(set(e['vm'] for e in df.to_dict('records')))

    context = {
        'page_obj': page_obj,
        'all_users': all_users,
        'all_vms': all_vms,
        'selected_user': user_filter,
        'selected_vm': vm_filter,
        'selected_result': result_filter,
        'user_role': user.get_role_display(),
        'is_admin': _is_admin(user),
        'username': user.username,
        'token': token,
    }
    return render(request, 'logger_app/event_log.html', context)


@admin_required
def view_encrypted_logs(request):
    from .encryption import encrypt_log, decrypt_log

    user = request.auth_user
    token = request.auth_token
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)

    if not list(log_dir.glob("*.enc")):
        df = generate_events()
        now_str = datetime.now().strftime('%Y%m%d_%H%M%S')

        attacker_df = df[df['user'] == 'Злоумышленник']
        attacker_records = [{'timestamp': str(r['timestamp']), 'user': r['user'], 'vm': r['vm'],
                              'action': r['action'], 'result': 'ЗАПРЕЩЕНО', 'reason': r['final_reason']}
                             for _, r in attacker_df.iterrows()]
        log1 = json.dumps({'type': 'attacker_events', 'generated': str(datetime.now()), 'events': attacker_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'attacker_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log1))

        denied_df = df[(df['user'] != 'Злоумышленник') & (df['policy_allowed'] == False)]
        denied_records = [{'timestamp': str(r['timestamp']), 'user': r['user'], 'vm': r['vm'],
                            'action': r['action'], 'result': 'ЗАПРЕЩЕНО', 'reason': r['policy_reason']}
                           for _, r in denied_df.iterrows()]
        log2 = json.dumps({'type': 'policy_violations', 'generated': str(datetime.now()), 'events': denied_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'policy_violations_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log2))

        anomaly_df = df[df['is_critical_anomaly'] == True]
        anomaly_records = [{'timestamp': str(r['timestamp']), 'user': r['user'], 'vm': r['vm'],
                             'action': r['action'], 'requests_per_second': int(r['requests_per_second']),
                             'result': 'ЗАБЛОКИРОВАНО', 'reason': r['final_reason']}
                            for _, r in anomaly_df.iterrows()]
        log3 = json.dumps({'type': 'frequency_anomalies', 'generated': str(datetime.now()), 'events': anomaly_records}, ensure_ascii=False, indent=2)
        with open(log_dir / f'anomalies_{now_str}.enc', 'w', encoding='utf-8') as f:
            f.write(encrypt_log(log3))

    encrypted_files = list(log_dir.glob("*.enc"))
    type_labels = {'attacker': 'События злоумышленника', 'policy_violations': 'Нарушения политики', 'anomalies': 'Аномалии частоты'}
    files_info = []
    for f in encrypted_files:
        label = f.name
        for key, rus in type_labels.items():
            if f.stem.startswith(key):
                label = rus
                break
        files_info.append({'name': f.name, 'label': label, 'size': f.stat().st_size,
                            'modified': datetime.fromtimestamp(f.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')})
    files_info.sort(key=lambda x: x['modified'], reverse=True)

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
        'username': user.username,
        'is_admin': True,
        'token': token,
    }
    return render(request, 'logger_app/encrypted_logs.html', context)


@csrf_exempt
@admin_required
def settings_view(request):
    policy_path = Path(__file__).parent / "migrations" / "policy.json"
    user = request.auth_user
    token = request.auth_token

    if request.method == 'POST':
        new_freq = int(request.POST.get('base_frequency', 2))
        new_percent = int(request.POST.get('minor_overhead', 20))
        new_block_sec = int(request.POST.get('block_seconds', 100))

        with open(policy_path, 'r', encoding='utf-8') as f:
            policy = json.load(f)

        policy['base_frequency_per_second'] = new_freq
        policy['minor_overhead_percent'] = new_percent
        policy['temporary_block_seconds'] = new_block_sec

        with open(policy_path, 'w', encoding='utf-8') as f:
            json.dump(policy, f, ensure_ascii=False, indent=2)

        log_dir = Path(__file__).parent / "logs"
        log_dir.mkdir(exist_ok=True)
        with open(log_dir / "audit.log", 'a', encoding='utf-8') as f:
            f.write(f"{datetime.now().isoformat()} | Admin {user.username} | freq={new_freq}, overhead={new_percent}, block_sec={new_block_sec}\n")

        return redirect(f'/logger/settings/?t={token}&saved=1')

    import math
    with open(policy_path, 'r', encoding='utf-8') as f:
        policy = json.load(f)

    base_freq = policy.get('base_frequency_per_second', 2)
    minor_overhead = policy.get('minor_overhead_percent', 20)
    block_sec = policy.get('temporary_block_seconds', 100)
    critical_threshold = math.ceil(base_freq * (1 + minor_overhead / 100))

    context = {
        'base_freq': base_freq,
        'minor_overhead': minor_overhead,
        'block_sec': block_sec,
        'critical_threshold': critical_threshold,
        'token': token,
        'saved': request.GET.get('saved') == '1',
    }
    return render(request, 'logger_app/settings.html', context)


def logout_view(request):
    token = _get_token(request)
    _invalidate_token(token)
    return redirect('/logger/login/')
