from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from .models import BehaviorLog


# =================================================
# MAIN HONEYPOT ENGINE
# =================================================
@csrf_exempt
def simulate_request(request):

    # --------- BASIC REQUEST INFO ---------
    ip = request.META.get(
        'HTTP_X_FORWARDED_FOR',
        request.META.get('REMOTE_ADDR', '0.0.0.0')
    )

    path = request.path.lower()
    method = request.method
    ua = request.META.get('HTTP_USER_AGENT', 'unknown').lower()
    query = request.GET.dict()

    behavior, _ = BehaviorLog.objects.get_or_create(
        ip_address=ip,
        defaults={
            'request_path': path,
            'request_method': method,
            'user_agent': ua,
            'request_count': 0,
            'failed_login_attempts': 0,
            'risk_score': 0,
            'risk_level': "NORMAL",
            'attack_type': "NORMAL"
        }
    )

    # --------- COUNTERS ---------
    behavior.request_count += 1

    if path.endswith("/login/") and method == "POST":
        behavior.failed_login_attempts += 1

    # --------- ATTACK DETECTION ---------

    # 1. Reconnaissance / Scanning
    recon_detected = any(p in path for p in [
        "/admin", "/.env", "/wp-login", "/phpmyadmin"
    ])

    # 2. SQL Injection
    sql_injection_detected = any(
        k in str(query).lower()
        for k in ["' or", "1=1", "union", "select", "--"]
    )

    # 3. Path Traversal
    path_traversal_detected = any(
        p in path for p in ["../", "..\\", "/etc/passwd"]
    )

    # 4. Command Injection
    command_injection_detected = any(
        c in str(query).lower()
        for c in ["; ls", "; whoami", "&&", "|"]
    )

    # 5. Bot Activity
    bot_detected = any(b in ua for b in [
        "curl", "python", "bot", "scanner"
    ])

    # 6. HTTP Method Abuse
    method_abuse_detected = method in ["PUT", "DELETE", "PATCH"]

    # 7. Credential Stuffing
    credential_stuffing_detected = behavior.failed_login_attempts >= 5

    # --------- RISK SCORE ---------
    risk_score = 0
    risk_score += behavior.request_count * 0.5
    risk_score += behavior.failed_login_attempts * 1

    if recon_detected:
        risk_score += 3
    if sql_injection_detected:
        risk_score += 4
    if path_traversal_detected:
        risk_score += 4
    if command_injection_detected:
        risk_score += 5
    if bot_detected:
        risk_score += 2
    if method_abuse_detected:
        risk_score += 3
    if credential_stuffing_detected:
        risk_score += 4

    behavior.risk_score = risk_score

    # --------- ATTACK CLASSIFICATION ---------
    if command_injection_detected:
        attack_type = "COMMAND_INJECTION"
    elif sql_injection_detected:
        attack_type = "SQL_INJECTION"
    elif path_traversal_detected:
        attack_type = "PATH_TRAVERSAL"
    elif credential_stuffing_detected:
        attack_type = "CREDENTIAL_STUFFING"
    elif recon_detected:
        attack_type = "RECONNAISSANCE"
    elif behavior.failed_login_attempts >= 3:
        attack_type = "BRUTE_FORCE"
    elif bot_detected:
        attack_type = "BOT_ACTIVITY"
    elif method_abuse_detected:
        attack_type = "HTTP_METHOD_ABUSE"
    else:
        attack_type = "NORMAL"

    behavior.attack_type = attack_type

    # --------- RISK LEVEL ---------
    if risk_score >= 12:
        behavior.risk_level = "MALICIOUS"
    elif risk_score >= 6:
        behavior.risk_level = "SUSPICIOUS"
    else:
        behavior.risk_level = "NORMAL"

    behavior.save()

    return JsonResponse({
        "ip": ip,
        "attack_type": attack_type,
        "risk_score": behavior.risk_score,
        "risk_level": behavior.risk_level
    })


# =================================================
# FAKE LOGIN PAGE (HONEYPOT UI)
# =================================================
@csrf_exempt
def fake_login(request):
    if request.method == "POST":
        simulate_request(request)
        return render(
            request,
            "login.html",
            {"error": "Invalid username or password"}
        )
    return render(request, "login.html")


# =================================================
# FAKE HOME PAGE
# =================================================
def fake_home(request):
    return render(request, "home.html")
