from django.contrib import admin
from .models import BehaviorLog

@admin.register(BehaviorLog)
class BehaviorLogAdmin(admin.ModelAdmin):
    list_display = (
        'ip_address',
        'request_count',
        'failed_login_attempts',
        'attack_type',   # ✅ ADD THIS
        'risk_score',
        'risk_level',
    )