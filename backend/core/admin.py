from django.contrib import admin
from .models import BehaviorLog

@admin.register(BehaviorLog)
class BehaviorLogAdmin(admin.ModelAdmin):
    list_display = (
        "ip_address",
        "request_path",
        "request_method",
        "request_count",
        "failed_login_attempts",
        "payload_size",
        "param_count",
        "keyword_count",
        "request_interval",
        "attack_type",
        "risk_score",
        "risk_level",
        "timestamp"
    )