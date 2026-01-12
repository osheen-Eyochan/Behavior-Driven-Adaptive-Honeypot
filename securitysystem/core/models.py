from django.db import models

class BehaviorLog(models.Model):
    ip_address = models.GenericIPAddressField()
    request_path = models.CharField(max_length=255)
    request_method = models.CharField(max_length=10)
    user_agent = models.TextField()

    failed_login_attempts = models.IntegerField(default=0)
    request_count = models.IntegerField(default=0)

    risk_score = models.FloatField(default=0.0)
    risk_level = models.CharField(
        max_length=20,
        choices=[
            ('NORMAL', 'Normal'),
            ('SUSPICIOUS', 'Suspicious'),
            ('MALICIOUS', 'Malicious'),
        ],
        default='NORMAL'
    )

    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.ip_address} - {self.risk_level}"
