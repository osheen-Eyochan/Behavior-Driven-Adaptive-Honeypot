from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.views.decorators.csrf import csrf_exempt
from .models import BehaviorLog
from django.db.models.functions import TruncMinute
from django.db.models import Count
from django.db.models import Sum
from django.utils import timezone
from datetime import timedelta
import json
import joblib
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

model = joblib.load(os.path.join(BASE_DIR, "attack_model.pkl"))
path_encoder = joblib.load(os.path.join(BASE_DIR, "path_encoder.pkl"))
method_encoder = joblib.load(os.path.join(BASE_DIR, "method_encoder.pkl"))
agent_encoder = joblib.load(os.path.join(BASE_DIR, "agent_encoder.pkl"))
attack_encoder = joblib.load(os.path.join(BASE_DIR, "attack_encoder.pkl"))


# =================================================
# ATTACK PRIORITY
# =================================================

ATTACK_PRIORITY = {
    "COMMAND_INJECTION": 7,
    "SQL_INJECTION": 6,
    "FILE_INCLUSION": 5,
    "PATH_TRAVERSAL": 4,
    "XSS_ATTACK": 4,
    "RECONNAISSANCE": 3,
    "HTTP_METHOD_ABUSE": 3,
    "CREDENTIAL_STUFFING": 3,
    "PARAMETER_POLLUTION": 3,
    "SENSITIVE_FILE_SCAN": 3,
    "API_ENUMERATION": 2,
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

            # --------- ML Prediction ---------

    try:
        encoded_path = path_encoder.transform([path])[0]
    except:
        encoded_path = 0   # fallback if unseen

    try:
        encoded_method = method_encoder.transform([method])[0]
    except:
        encoded_method = 0

    try:
        encoded_agent = agent_encoder.transform([ua])[0]
    except:
        encoded_agent = 0


    ml_features = [[
        encoded_path,
        encoded_method,
        encoded_agent,
        behavior.failed_login_attempts,
        behavior.request_count
    ]]

    ml_prediction_encoded = model.predict(ml_features)[0]
    ml_attack_type = attack_encoder.inverse_transform([ml_prediction_encoded])[0]

    




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


# -------- XSS --------
    xss_detected = any(x in pl for x in [
        "<script", "javascript:", "onerror=",
        "onload=", "<img", "<iframe"
    ])

# -------- FILE INCLUSION --------
    file_inclusion_detected = any(f in pl for f in [
        "/etc/passwd",
        "boot.ini",
        "windows/system32",
        ".env",
        ".git"
])



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

    if xss_detected:
        risk_score += 3

    if file_inclusion_detected:
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

    elif file_inclusion_detected:
        detected_attack = "FILE_INCLUSION"

    elif xss_detected:
        detected_attack = "XSS_ATTACK"

    
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

    print("Rule:", detected_attack)
    print("ML:", ml_attack_type)
    old_attack = behavior.attack_type


    if ATTACK_PRIORITY.get(detected_attack, 0) >= ATTACK_PRIORITY.get(old_attack, 0):

        behavior.attack_type = detected_attack
                # If ML disagrees, increase suspicion
        if detected_attack != ml_attack_type:
            behavior.risk_score += 2



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

def security_dashboard(request):

    # -------- Attack Distribution --------
    attack_counts = BehaviorLog.objects.values("attack_type") \
        .annotate(total=Count("id"))

    # -------- Risk Distribution --------
    risk_counts = BehaviorLog.objects.values("risk_level") \
        .annotate(total=Count("id"))

    # -------- Top Attacker IPs --------
    top_ips = BehaviorLog.objects.order_by("-risk_score")[:5]

    # -------- Timeline (per minute) --------
    timeline = BehaviorLog.objects \
        .annotate(time=TruncMinute("timestamp")) \
        .values("time") \
        .annotate(count=Count("id")) \
        .order_by("time")

    # -------- GLOBAL THREAT LEVEL --------
    malicious_count = BehaviorLog.objects.filter(
        risk_level="MALICIOUS"
    ).count()

    suspicious_count = BehaviorLog.objects.filter(
        risk_level="SUSPICIOUS"
    ).count()

    if malicious_count > 5:
        threat_level = "CRITICAL"
    elif suspicious_count > 5:
        threat_level = "ELEVATED"
    else:
        threat_level = "NORMAL"

    context = {
        "attack_counts": attack_counts,
        "risk_counts": risk_counts,
        "top_ips": top_ips,
        "timeline": timeline,
        "threat_level": threat_level
    }

    return render(request, "dashboard.html", context)

def attacker_profile(request, ip):

    # All logs for this IP (latest first)
    logs = BehaviorLog.objects.filter(
        ip_address=ip
    ).order_by("-timestamp")

    # -------- Summary Metrics --------
    total_requests = logs.count()

    failed_logins = logs.aggregate(
        total=Sum("failed_login_attempts")
    )["total"] or 0

    latest = logs.first()

    context = {
        "ip": ip,
        "logs": logs[:20],  # show recent activity
        "total_requests": total_requests,
        "failed_logins": failed_logins,
        "latest": latest
    }

    return render(request, "attacker_profile.html", context)


def behavior_log_page(request):
        logs = BehaviorLog.objects.all().order_by("-timestamp")
        return render(request, "blog.html", {"logs": logs})