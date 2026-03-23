import os
import sys
import django
import csv

print("STARTING EXPORT...")

try:
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))

    os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.securitysystem.settings")
    django.setup()

    from core.models import BehaviorLog

    logs = BehaviorLog.objects.all()

    print("Total rows:", logs.count())   # ✅ DEBUG

    file_path = r"C:\Users\USER\OneDrive\Desktop\dataset.csv"
    print("Saving to:", file_path)

    with open(file_path, "w", newline="") as f:
        writer = csv.writer(f)

        writer.writerow([
            "request_count",
            "failed_login_attempts",
            "payload_size",
            "param_count",
            "keyword_count",
            "request_interval",
            "same_user_attempts",
            "attack_type"
        ])

        for log in logs:
            writer.writerow([
                log.request_count,
                log.failed_login_attempts,
                log.payload_size,
                log.param_count,
                log.keyword_count,
                log.request_interval,
                log.same_user_attempts,
                log.attack_type
            ])

    print("DONE EXPORT ✅")

except Exception as e:
    print("ERROR OCCURRED ❌")
    print(e)