import requests
import random
import time


# ======================
# CONFIG
# ======================

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = BASE_URL + "/login/"

TOTAL_REQUESTS = 10000


CORRECT_USERS = {
    "admin": "admin@123",
    "user1": "user1@123"
}

USERNAMES = ["admin", "user1", "test", "guest"]
PASSWORDS = ["123456", "password", "admin123", "root", "qwerty"]


# ======================
# ATTACK TYPES
# ======================

ATTACK_TYPES = [
    "NORMAL",
    "BRUTE_FORCE",
    "SQL_INJECTION",
    "PATH_TRAVERSAL",
    "COMMAND_INJECTION",
    "RECONNAISSANCE",
    "HTTP_METHOD_ABUSE",
    "BOT_ACTIVITY"
]


# ======================
# IP GENERATION
# ======================

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


# Create attackers
ACTIVE_IPS = [random_ip() for _ in range(1000)]


# Assign ONE attack per IP
IP_PROFILE = {}

for ip in ACTIVE_IPS:
    IP_PROFILE[ip] = random.choice(ATTACK_TYPES)


# ======================
# HEADERS
# ======================

HUMAN_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

BOT_HEADERS = {
    "User-Agent": "python-requests/2.28"
}


# ======================
# ATTACK BEHAVIOR
# ======================

def normal_login():
    u = random.choice(list(CORRECT_USERS.keys()))
    p = CORRECT_USERS[u]

    return "POST", LOGIN_URL, {"username": u, "password": p}, HUMAN_HEADERS


def brute_force():
    u = random.choice(USERNAMES)
    p = random.choice(PASSWORDS)

    return "POST", LOGIN_URL, {"username": u, "password": p}, HUMAN_HEADERS


def sql_attack():
    payload = "' OR 1=1 --"

    return "POST", LOGIN_URL, {
        "username": payload,
        "password": payload
    }, HUMAN_HEADERS


def path_attack():
    file = "../../etc/passwd"

    return "GET", LOGIN_URL + "?file=" + file, None, HUMAN_HEADERS


def command_attack():
    cmd = "admin && dir"

    return "POST", LOGIN_URL, {"cmd": cmd}, HUMAN_HEADERS


def recon_attack():
    path = "/admin/"

    return "GET", BASE_URL + path, None, HUMAN_HEADERS


def method_abuse():
    return "DELETE", LOGIN_URL, None, HUMAN_HEADERS


def bot_activity():
    return "POST", LOGIN_URL, {
        "username": "bot",
        "password": "scan"
    }, BOT_HEADERS


# ======================
# MAIN
# ======================

print("\nStarting Realistic Attack Simulation...\n")


for i in range(TOTAL_REQUESTS):

    # Pick attacker
    ip = random.choice(ACTIVE_IPS)

    attack_type = IP_PROFILE[ip]


    # Select behavior
    if attack_type == "NORMAL":
        method, url, data, headers = normal_login()

    elif attack_type == "BRUTE_FORCE":
        method, url, data, headers = brute_force()

    elif attack_type == "SQL_INJECTION":
        method, url, data, headers = sql_attack()

    elif attack_type == "PATH_TRAVERSAL":
        method, url, data, headers = path_attack()

    elif attack_type == "COMMAND_INJECTION":
        method, url, data, headers = command_attack()

    elif attack_type == "RECONNAISSANCE":
        method, url, data, headers = recon_attack()

    elif attack_type == "HTTP_METHOD_ABUSE":
        method, url, data, headers = method_abuse()

    else:  # BOT
        method, url, data, headers = bot_activity()


    headers = headers.copy()
    headers["X-Forwarded-For"] = ip


    try:

        if method == "POST":

            r = requests.post(
                url,
                json=data,
                headers=headers,
                timeout=5
            )

        elif method == "GET":

            r = requests.get(
                url,
                headers=headers,
                timeout=5
            )

        else:

            r = requests.request(
                method,
                url,
                headers=headers,
                timeout=5
            )


        print(
            f"{i+1:04d} | {ip:15} | {attack_type:18} | {r.status_code}"
        )


    except Exception as e:

        print("Error:", e)


    time.sleep(random.uniform(0.5, 2))


print("\nFinished Simulation.")
