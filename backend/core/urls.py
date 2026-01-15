from django.urls import path
from .views import simulate_request, fake_login, fake_home

urlpatterns = [

    # ---------------- Fake Honeypot Website ----------------
    path('', fake_home),                 # Fake homepage
    path('login/', fake_login),          # Brute force / credential stuffing

    # ---------------- Attack Simulation Endpoints ----------------
    path('admin-panel/', simulate_request),  # Fake admin access (RECON)
    path('.env', simulate_request),           # Config probing
    path('search/', simulate_request),        # SQL Injection attempts
    path('download/', simulate_request),      # Path Traversal
    path('exec/', simulate_request),          # Command Injection
    path('update/', simulate_request),        # HTTP Method abuse
]
