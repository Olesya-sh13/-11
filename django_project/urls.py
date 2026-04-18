from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('logger/', include('logger_app.urls')),
    path('', RedirectView.as_view(url='/logger/', permanent=False)),
]