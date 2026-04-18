from django.db import models
from django.contrib.auth.models import AbstractUser

class User(AbstractUser):
    """
    Расширенная модель пользователя.
    AbstractUser уже содержит username, password, email, first_name, last_name.
    Мы добавляем только поле 'role' для определения прав доступа.
    """

    ROLE_CHOICES = [
        ('admin', 'Администратор'),
        ('auditor', 'Аудитор'),
    ]

    role = models.CharField(
        max_length=20, 
        choices=ROLE_CHOICES, 
        default='operator',
        verbose_name='Роль пользователя'
    )

    def __str__(self):
        return f"{self.username} ({self.get_role_display()})"