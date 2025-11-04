from django.urls import path, include

urlpatterns = [
    path('ip_tracking/', include('ip_tracking.urls')),
]
