from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .models import BehaviorLog

import json


# =================================================
# ATTACK PRIORITY
# =================================================

ATTACK_PRIORITY = {
    "COMMAND_INJECTION": 6,
    "SQL_INJECTION": 5,
    "PATH_TRAVERSAL": 4,
    "RECONNAISSANCE": 3,
    "HTTP_METHOD_ABUSE": 3,
    "CREDENTIAL_STUFFING": 3,
    "BRUTE_FORCE": 2,
    "BOT_ACTIVITY": 1,
    "NORMAL": 0
}


# =================================================
# MAIN ENGINE
# =================================================
@csrf_exempt
def simulate_request(request):

    # --------- IP ---------

    ip = request.headers.get("X-Forwarded-For")

    if ip:
        ip = ip.split(",")[0]
    else:
        ip = request.META.get("REMOTE_ADDR", "0.0.0.0")


    # --------- BASIC INFO ---------

    path = request.path.lower()
    method = request.method
    ua = request.META.get("HTTP_USER_AGENT", "unknown").lower()

    query = request.GET.dict()
    post_data = request.POST.dict()


    # --------- RAW BODY (JSON SUPPORT) ---------

    raw_body = ""

    try:
        raw_body = request.body.decode("utf-8")
    except:
        pass


    payload = str(query) + str(post_data) + raw_body


    # --------- PROFILE ---------

    behavior, created = BehaviorLog.objects.get_or_create(

        ip_address=ip,

        defaults={
            "request_path": path,
            "request_method": method,
            "user_agent": ua,
            "request_count": 0,
            "failed_login_attempts": 0,
            "risk_score": 0,
            "risk_level": "NORMAL",
            "attack_type": "NORMAL"
        }
    )


    behavior.request_path = path
    behavior.request_method = method
    behavior.user_agent = ua

    behavior.request_count += 1


    # =================================================
    # FAILED LOGIN
    # =================================================

    if "login" in path and method == "POST":

        username = request.POST.get("username")
        password = request.POST.get("password")


        if not username or not password:

            try:
                body = json.loads(raw_body)
                username = body.get("username")
                password = body.get("password")
            except:
                username = None
                password = None


        valid_users = {
            "admin": "admin@123",
            "user1": "user1@123"
        }


        if username and password:

            if username not in valid_users or valid_users.get(username) != password:
                behavior.failed_login_attempts += 1


    # =================================================
    # ATTACK DETECTION
    # =================================================

    pl = payload.lower()


    recon_detected = any(p in path for p in [
    "admin-panel",
    "env",
    "wp-login",
    "phpmyadmin"
])



    sql_injection_detected = any(
        k in pl for k in [
            "' or", "1=1", "union", "select",
            "--", "'--", "information_schema"
        ]
    )


    path_traversal_detected = any(
        p in pl for p in [
            "../", "..\\", "/etc/passwd",
            "boot.ini", "windows/system32"
        ]
    )


    command_injection_detected = any(
        c in pl for c in [
            ";", "&&", "|", "`",
            "whoami", "netstat",
            "dir", "id", "ping"
        ]
    )


    bot_detected = any(b in ua for b in [
        "curl", "python", "bot", "scanner",
        "wget", "httpclient", "libwww"
    ])


    method_abuse_detected = method in ["PUT", "DELETE", "PATCH"]


    credential_stuffing_detected = behavior.failed_login_attempts >= 5


    # =================================================
    # RISK SCORE
    # =================================================

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


    # =================================================
    # CLASSIFICATION
    # =================================================

    detected_attack = "NORMAL"


    if command_injection_detected:
        detected_attack = "COMMAND_INJECTION"

    elif sql_injection_detected:
        detected_attack = "SQL_INJECTION"

    elif path_traversal_detected:
        detected_attack = "PATH_TRAVERSAL"

    elif recon_detected:
        detected_attack = "RECONNAISSANCE"

    elif method_abuse_detected:
        detected_attack = "HTTP_METHOD_ABUSE"

    elif behavior.failed_login_attempts >= 5:
        detected_attack = "CREDENTIAL_STUFFING"

    elif behavior.failed_login_attempts >= 3:
        detected_attack = "BRUTE_FORCE"

    elif bot_detected:
        detected_attack = "BOT_ACTIVITY"


    old_attack = behavior.attack_type


    if ATTACK_PRIORITY.get(detected_attack, 0) >= ATTACK_PRIORITY.get(old_attack, 0):

        behavior.attack_type = detected_attack


    # =================================================
    # RISK LEVEL
    # =================================================

    if behavior.risk_score >= 12:
        behavior.risk_level = "MALICIOUS"

    elif behavior.risk_score >= 6:
        behavior.risk_level = "SUSPICIOUS"

    else:
        behavior.risk_level = "NORMAL"


    behavior.save()


    # =================================================
    # RESPONSE
    # =================================================

    if behavior.risk_level == "MALICIOUS":

        return JsonResponse(
            {"error": "Access Denied. Malicious activity detected."},
            status=403
        )


    if behavior.risk_level == "SUSPICIOUS":

        return redirect("/")


    return JsonResponse({

        "ip": ip,
        "attack_type": behavior.attack_type,
        "risk_score": behavior.risk_score,
        "risk_level": behavior.risk_level
    })



# =================================================
# FAKE LOGIN
# =================================================
@csrf_exempt
def fake_login(request):

    simulate_request(request)

    if request.method == "POST":

        return render(request, "login.html", {
            "error": "Invalid username or password"
        })

    return render(request, "login.html")



# =================================================
# HOME
# =================================================
def fake_home(request):

    return render(request, "home.html")
