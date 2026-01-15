from django.contrib import admin
from .models import BehaviorLog

@admin.register(BehaviorLog)
class BehaviorLogAdmin(admin.ModelAdmin):
    list_display = (
        'ip_address',
        'request_count',
        'failed_login_attempts',
        'risk_score',
        'risk_level'
    )
    list_filter = ('risk_level',)
    search_fields = ('ip_address',)
