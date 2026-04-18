from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.http import HttpResponse

urlpatterns = [
    path('admin/', admin.site.urls),
    path('logger/', include('logger_app.urls')),
    path('favicon.ico', lambda request: HttpResponse(status=204)),
    path('', RedirectView.as_view(url='/logger/', permanent=False)),
]