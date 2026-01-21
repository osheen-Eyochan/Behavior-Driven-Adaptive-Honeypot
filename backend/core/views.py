from django.http import JsonResponse
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt
from .models import BehaviorLog


# =================================================
# MAIN HONEYPOT ENGINE
# =================================================
@csrf_exempt
def simulate_request(request):

    # --------- GET REAL / SIMULATED IP ADDRESS ---------
    ip = request.headers.get('X-Forwarded-For')
    if ip:
        ip = ip.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR', '0.0.0.0')

    path = request.path.lower()
    method = request.method
    ua = request.META.get('HTTP_USER_AGENT', 'unknown').lower()
    query = request.GET.dict()
    post_data = request.POST.dict()

    payload = str(query) + str(post_data)

    # --------- CREATE / GET BEHAVIOR PROFILE ---------
    behavior, created = BehaviorLog.objects.get_or_create(
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

    # Always update latest request info
    behavior.request_path = path
    behavior.request_method = method
    behavior.user_agent = ua

    # --------- UPDATE COUNTERS ---------
    behavior.request_count += 1

    # 🔥 FAILED LOGIN DETECTION
    if "login" in path and method == "POST":
        behavior.failed_login_attempts += 1

    # --------- ATTACK DETECTION ---------

    # 1. Reconnaissance / Scanning
    recon_detected = any(p in path for p in [
        "/admin", "/.env", "/wp-login", "/phpmyadmin"
    ])

    # 2. SQL Injection
    sql_injection_detected = any(
        k in payload.lower()
        for k in ["' or", "1=1", "union", "select", "--", "'--"]
    )

    # 3. 🔥 PATH TRAVERSAL
    path_traversal_detected = any(
        p in (path + payload).lower()
        for p in ["../", "..\\", "/etc/passwd", "boot.ini"]
    )

    # 4. 🔥 COMMAND INJECTION DETECTION
    command_injection_detected = any(
        c in payload.lower()
        for c in [
            "; ls", ";whoami", "; id",
            "&&", "|", "`",
            "cat /etc/passwd",
            "dir", "ping", "netstat"
        ]
    )

    # 5. 🔥 BOT ACTIVITY DETECTION
    bot_detected = any(b in ua for b in [
        "curl", "python", "bot", "scanner", "wget", "httpclient", "libwww"
    ])

    # 6. HTTP Method Abuse
    method_abuse_detected = method in ["PUT", "DELETE", "PATCH"]

    # 7. Credential Stuffing
    credential_stuffing_detected = behavior.failed_login_attempts >= 5

    # --------- RISK SCORE CALCULATION ---------
    risk_score = 0

    risk_score += behavior.request_count * 0.3
    risk_score += behavior.failed_login_attempts * 1

    if recon_detected:
        risk_score += 2
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

    behavior.risk_score = round(risk_score, 2)

    # --------- 🔥 ATTACK CLASSIFICATION ---------

    # Login based attacks FIRST
    if behavior.failed_login_attempts >= 5:
        attack_type = "CREDENTIAL_STUFFING"
    elif behavior.failed_login_attempts >= 3:
        attack_type = "BRUTE_FORCE"

    # Direct exploitation attacks
    elif command_injection_detected:
        attack_type = "COMMAND_INJECTION"
    elif sql_injection_detected:
        attack_type = "SQL_INJECTION"
    elif path_traversal_detected:
        attack_type = "PATH_TRAVERSAL"

    # Automated / scanning attacks
    elif bot_detected:
        attack_type = "BOT_ACTIVITY"
    elif recon_detected:
        attack_type = "RECONNAISSANCE"
    elif method_abuse_detected:
        attack_type = "HTTP_METHOD_ABUSE"
    else:
        attack_type = "NORMAL"

    behavior.attack_type = attack_type

    # --------- RISK LEVEL ASSIGNMENT ---------
    if behavior.risk_score >= 12:
        behavior.risk_level = "MALICIOUS"
    elif behavior.risk_score >= 6:
        behavior.risk_level = "SUSPICIOUS"
    else:
        behavior.risk_level = "NORMAL"

    behavior.save()

    # --------- ADAPTIVE RESPONSE ---------
    if behavior.risk_level == "MALICIOUS":
        return JsonResponse(
            {"error": "Access Denied. Suspicious activity detected."},
            status=403
        )

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

    simulate_request(request)

    if request.method == "POST":
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
