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

#BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#model = joblib.load(os.path.join(BASE_DIR, "attack_model.pkl"))
#path_encoder = joblib.load(os.path.join(BASE_DIR, "path_encoder.pkl"))
#method_encoder = joblib.load(os.path.join(BASE_DIR, "method_encoder.pkl"))
#agent_encoder = joblib.load(os.path.join(BASE_DIR, "agent_encoder.pkl"))
#attack_encoder = joblib.load(os.path.join(BASE_DIR, "attack_encoder.pkl"))


# =================================================
# ATTACK PRIORITY
# =================================================

ATTACK_PRIORITY = {
    "COMMAND_INJECTION": 8,
    "SQL_INJECTION": 7,
    "FILE_INCLUSION": 6,
    "PATH_TRAVERSAL": 6,
    "XSS_ATTACK": 5,
    "SENSITIVE_FILE_SCAN": 5,
    "PARAMETER_POLLUTION": 4,
    "RECONNAISSANCE": 3,
    "HTTP_METHOD_ABUSE": 3,
    "CREDENTIAL_STUFFING": 4,
    "BRUTE_FORCE": 3,
    "BOT_ACTIVITY": 3
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


    print("PATH:", request.path)
    print("POST DATA:", request.POST)
    print("RAW BODY:", request.body)


    # --------- BASIC INFO ---------

    path = request.path.lower()
    method = request.method
    ua = request.META.get("HTTP_USER_AGENT", "unknown").lower()

    query = request.GET.dict()
    post_data = request.POST.dict()

# handle JSON payload
    if not post_data and request.body:
        try:
            post_data = json.loads(request.body.decode("utf-8"))
        except:
            post_data = {}


    # --------- RAW BODY (JSON SUPPORT) ---------

    raw_body = ""

    try:
        raw_body = request.body.decode("utf-8")
    except:
        pass


    payload = " ".join(list(query.values()) + list(post_data.values())) + " " + raw_body

    payload_size = len(payload)

    param_count = len(query) + len(post_data)

    suspicious_keywords = [
        "select", "union", "<script", "javascript:",
        "../", "/etc/passwd", "whoami", "ping"
    ]

    keyword_count = sum(k in payload.lower() for k in suspicious_keywords)

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
            "attack_type": "NORMAL",
            "request_interval": 0,
            "last_seen": timezone.now()
        }
    )

    # ✅ ALWAYS UPDATE SAME ROW
    behavior.request_count += 1

    # update fields
    behavior.request_path = path
    behavior.request_method = method
    behavior.user_agent = ua

    behavior.payload_size = payload_size
    behavior.param_count = param_count
    behavior.keyword_count = keyword_count

    # optional
    behavior.last_seen = timezone.now()

            # --------- ML Prediction ---------

    #try:
    #    encoded_path = path_encoder.transform([path])[0]
    #except:
    #    encoded_path = 0   # fallback if unseen

    #try:
     #   encoded_method = method_encoder.transform([method])[0]
    #except:
     #   encoded_method = 0

    #try:
   #     encoded_agent = agent_encoder.transform([ua])[0]
    #except:
     #   encoded_agent = 0


    #ml_features = [[
     #   encoded_path,
      #  encoded_method,
       ##behavior.failed_login_attempts,
        #behavior.request_count,
        #payload_size,
        #param_count,
        #keyword_count
    #]]

    #ml_prediction_encoded = model.predict(ml_features)[0]
    #ml_attack_type = attack_encoder.inverse_transform([ml_prediction_encoded])[0]

    




    # =================================================
    # FAILED LOGIN
    # =================================================

    # =================================================
# FAILED LOGIN + PATTERN TRACKING
# =================================================

    username = None
    password = None

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

                # ✅ initialize safely
                if not hasattr(behavior, "same_user_attempts") or behavior.same_user_attempts is None:
                    behavior.same_user_attempts = 0

                # ✅ pattern tracking
                if behavior.last_username == username:
                    behavior.same_user_attempts += 1
                else:
                    behavior.same_user_attempts = 1

                behavior.last_username = username


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
        p in pl for p in ["../", "..\\"]
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
    # FILE INCLUSION → direct file access
    file_inclusion_detected = any(
        f in pl for f in ["/etc/passwd", ".env", ".git"]
    )
    parameter_pollution_detected = len(request.GET) > 5

    sensitive_file_scan_detected = any(f in path for f in [
    ".env",
    ".git",
    ".htaccess",
    ".htpasswd",
    "config.php"
])
    



    # =================================================
    # RISK SCORE
    # =================================================

   

    # =================================================
    # CLASSIFICATION
    # =================================================

    detected_attacks = []

    if command_injection_detected:
        detected_attacks.append("COMMAND_INJECTION")

    if sql_injection_detected:
        detected_attacks.append("SQL_INJECTION")

    if path_traversal_detected:
        detected_attacks.append("PATH_TRAVERSAL")

    if file_inclusion_detected:
        detected_attacks.append("FILE_INCLUSION")

    if xss_detected:
        detected_attacks.append("XSS_ATTACK")

    if sensitive_file_scan_detected:
        detected_attacks.append("SENSITIVE_FILE_SCAN")

    if parameter_pollution_detected:
        detected_attacks.append("PARAMETER_POLLUTION")

    if recon_detected:
        detected_attacks.append("RECONNAISSANCE")

    if method_abuse_detected:
        detected_attacks.append("HTTP_METHOD_ABUSE")

    if bot_detected:
        detected_attacks.append("BOT_ACTIVITY")

    if username and password:

        if username not in valid_users or valid_users.get(username) != password:
            behavior.failed_login_attempts += 1

        # track username pattern
            if behavior.last_username == username:
                behavior.same_user_attempts += 1
            else:
                behavior.same_user_attempts = 1

            behavior.last_username = username
    # Credential stuffing → same username repeatedly
    if getattr(behavior, "same_user_attempts", 0) >= 5:
        detected_attacks.append("CREDENTIAL_STUFFING")

    # Brute force → many failed attempts (different users)
    elif behavior.failed_login_attempts >= 5:
        detected_attacks.append("BRUTE_FORCE")

    # FINAL SELECTION (priority-based)
    if detected_attacks:
        detected_attacks.sort(
            key=lambda x: ATTACK_PRIORITY.get(x, 0),
            reverse=True
        )
        behavior.attack_type = detected_attacks[0]
    else:
        behavior.attack_type = "NORMAL"
    #print("Rule:", detected_attack)
    #print("ML:", ml_attack_type)
   # old_attack = behavior.attack_type


   # if ATTACK_PRIORITY.get(detected_attack, 0) >= ATTACK_PRIORITY.get(old_attack, 0):

       
                # If ML disagrees, increase suspicion
      #  if detected_attack != ml_attack_type:
       #     behavior.risk_score += 2


 # =========================
# STRUCTURED RISK SCORING
# =========================

    risk_score = 0

    # 1. Behavior score
    risk_score += min(behavior.request_count * 0.3, 5)
    risk_score += behavior.failed_login_attempts * 1.2

    # 2. Attack severity (use your priority table)
    for attack in detected_attacks:
        risk_score += ATTACK_PRIORITY.get(attack, 0)

    # 3. Frequency boost (VERY IMPORTANT)
    if behavior.request_count > 10:
        risk_score += 2

    if behavior.request_count > 20:
        risk_score += 3

    behavior.risk_score = round(risk_score, 2)

    # =================================================
    # RISK LEVEL
    # =================================================

    if behavior.risk_score >= 15:
        behavior.risk_level = "MALICIOUS"

    elif behavior.risk_score >= 8:
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

    print("Total logs:", logs.count())   # debugging

    context = {
        "logs": logs
    }

    return render(request, "blog.html", context)