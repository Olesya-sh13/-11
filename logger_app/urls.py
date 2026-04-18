from django.urls import path
from . import views

app_name = 'logger_app'

urlpatterns = [
    path('', views.log_dashboard, name='dashboard'),
    path('events/', views.event_log, name='event_log'),
    path('encrypted-logs/', views.view_encrypted_logs, name='encrypted_logs'),
    path('settings/', views.settings_view, name='settings'),
    path('login/', views.custom_login, name='login'),
    path('logout/', views.logout_view, name='logout'),
]