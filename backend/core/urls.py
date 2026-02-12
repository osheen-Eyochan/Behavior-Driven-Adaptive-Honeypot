from django.urls import path
from .views import simulate_request, fake_login, fake_home

urlpatterns = [

    # Fake website
    path('', fake_home),
    path('login/', fake_login),

    # Honeypot endpoints
    path('admin-panel/', simulate_request),   # Recon
    path('env/', simulate_request),           # Fake .env
    path('search/', simulate_request),        # SQLi
    path('download/', simulate_request),      # Path traversal
    path('exec/', simulate_request),          # Command injection
    path('update/', simulate_request),        # HTTP abuse
]
