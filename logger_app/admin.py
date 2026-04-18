from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import User

class CustomUserAdmin(UserAdmin):
    """
    Настройка отображения пользователей в админ-панели
    """
    list_display = ('username', 'get_role_display', 'is_staff', 'is_active')
    list_filter = ('role', 'is_staff', 'is_active')

    # Добавляем поле role в форму редактирования пользователя
    fieldsets = UserAdmin.fieldsets + (
        ('Дополнительно', {'fields': ('role',)}),
    )

    # Добавляем поле role в форму создания нового пользователя
    add_fieldsets = UserAdmin.add_fieldsets + (
        ('Дополнительно', {'fields': ('role',)}),
    )

admin.site.register(User, CustomUserAdmin)