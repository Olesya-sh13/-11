"""
Команда для создания пользователей из policy.json с разными паролями
Запуск: python manage.py create_users_from_policy
"""

import json
from pathlib import Path
from django.core.management.base import BaseCommand
from django.contrib.auth.hashers import make_password
from logger_app.models import User

class Command(BaseCommand):
    help = 'Создаёт пользователей из policy.json с разными паролями'

    def handle(self, *args, **options):
        # Загружаем policy.json
        policy_path = Path(__file__).parent.parent.parent / "migrations" / "policy.json"
        with open(policy_path, 'r', encoding='utf-8') as f:
            policy = json.load(f)

        # Соответствие ролей в policy и в нашей модели
        role_mapping = {
            'Геолог': 'geologist',
            'Петрофизик': 'petrophysicist',
            'Инженер-разработчик': 'engineer',
            'Оператор': 'operator',
            'Аудитор': 'auditor',
        }

        # Задаём разные пароли для каждого пользователя
        passwords = {
            'Геолог': 'geo2024',
            'Петрофизик': 'petro2024',
            'Инженер-разработчик': 'eng2024',
            'Оператор': 'oper2024',
            'Аудитор': 'audit2024',
        }

        # Создаём пользователей
        for user_name in policy['users']:
            if user_name in role_mapping:
                password = passwords.get(user_name, 'default123')
                user, created = User.objects.get_or_create(
                    username=user_name,
                    defaults={
                        'role': role_mapping[user_name],
                        'password': make_password(password),
                        'is_active': True,
                    }
                )
                if created:
                    self.stdout.write(self.style.SUCCESS(f'Создан пользователь: {user_name} (пароль: {password})'))
                else:
                    user.password = make_password(password)
                    user.save()
                    self.stdout.write(f'Обновлён пароль для пользователя: {user_name}')

        # Создаём администратора
        admin, created = User.objects.get_or_create(
            username='admin',
            defaults={
                'role': 'admin',
                'password': make_password('Admin2024!'),
                'is_superuser': True,
                'is_staff': True,
                'is_active': True,
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS('Создан администратор: admin (пароль: Admin2024!)'))

        self.stdout.write(self.style.SUCCESS('\nГотово!'))