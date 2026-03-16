import requests
import random
import time

BASE_URL = "http://127.0.0.1:8000"
LOGIN_URL = BASE_URL + "/login/"

TOTAL_REQUESTS = 10000


# -------------------------
# USERS
# -------------------------

CORRECT_USERS = {
    "admin": "admin@123",
    "user1": "user1@123"
}

USERNAMES = ["admin", "user1", "guest", "test"]
PASSWORDS = ["123456", "password", "admin123", "root"]


# -------------------------
# ATTACK TYPES
# -------------------------

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
    "HTTP_METHOD_ABUSE",
    "BOT_ACTIVITY"
]


# -------------------------
# IP GENERATION
# -------------------------

def random_ip():
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


ACTIVE_IPS = [random_ip() for _ in range(500)]

IP_PROFILE = {ip: random.choice(ATTACK_TYPES) for ip in ACTIVE_IPS}


# -------------------------
# HEADERS
# -------------------------

HUMAN_HEADERS = {
    "User-Agent": "Mozilla/5.0"
}

BOT_HEADERS = {
    "User-Agent": "python-requests/2.28"
}


# -------------------------
# ATTACK FUNCTIONS
# -------------------------

def normal():
    u = random.choice(list(CORRECT_USERS.keys()))
    p = CORRECT_USERS[u]

    return "POST", LOGIN_URL, {"username": u, "password": p}, HUMAN_HEADERS


def brute_force():
    u = random.choice(USERNAMES)
    p = random.choice(PASSWORDS)

    return "POST", LOGIN_URL, {"username": u, "password": p}, HUMAN_HEADERS


def credential_stuffing():
    u = "admin"
    p = random.choice(PASSWORDS)

    return "POST", LOGIN_URL, {"username": u, "password": p}, HUMAN_HEADERS


def sql_injection():
    payload = "' OR 1=1 --"

    return "POST", LOGIN_URL, {"username": payload, "password": payload}, HUMAN_HEADERS


def command_injection():
    payload = "admin && whoami"

    return "POST", LOGIN_URL, {"username": payload, "password": "test"}, HUMAN_HEADERS


def path_traversal():
    url = LOGIN_URL + "?file=../../etc/passwd"

    return "GET", url, None, HUMAN_HEADERS


def file_inclusion():
    url = LOGIN_URL + "?page=/etc/passwd"

    return "GET", url, None, HUMAN_HEADERS


def xss():
    payload = "<script>alert(1)</script>"

    return "POST", LOGIN_URL, {"username": payload, "password": "test"}, HUMAN_HEADERS


def parameter_pollution():
    params = {
        "a": "1",
        "b": "2",
        "c": "3",
        "d": "4",
        "e": "5",
        "f": "6"
    }

    return "GET", LOGIN_URL, params, HUMAN_HEADERS


def sensitive_file_scan():
    url = BASE_URL + "/.env"

    return "GET", url, None, HUMAN_HEADERS


def method_abuse():
    return "DELETE", LOGIN_URL, None, HUMAN_HEADERS


def bot_activity():
    return "POST", LOGIN_URL, {"username": "bot", "password": "scan"}, BOT_HEADERS


# -------------------------
# MAIN LOOP
# -------------------------

print("\nStarting Attack Simulation...\n")

for i in range(TOTAL_REQUESTS):

    ip = random.choice(ACTIVE_IPS)
    attack = IP_PROFILE[ip]

    if attack == "NORMAL":
        method, url, data, headers = normal()

    elif attack == "BRUTE_FORCE":
        method, url, data, headers = brute_force()

    elif attack == "CREDENTIAL_STUFFING":
        method, url, data, headers = credential_stuffing()

    elif attack == "SQL_INJECTION":
        method, url, data, headers = sql_injection()

    elif attack == "COMMAND_INJECTION":
        method, url, data, headers = command_injection()

    elif attack == "PATH_TRAVERSAL":
        method, url, data, headers = path_traversal()

    elif attack == "FILE_INCLUSION":
        method, url, data, headers = file_inclusion()

    elif attack == "XSS_ATTACK":
        method, url, data, headers = xss()

    elif attack == "PARAMETER_POLLUTION":
        method, url, data, headers = parameter_pollution()

    elif attack == "SENSITIVE_FILE_SCAN":
        method, url, data, headers = sensitive_file_scan()

    elif attack == "HTTP_METHOD_ABUSE":
        method, url, data, headers = method_abuse()

    else:
        method, url, data, headers = bot_activity()


    headers = headers.copy()
    headers["X-Forwarded-For"] = ip


    try:

        if method == "POST":
            r = requests.post(url, json=data, headers=headers)

        elif method == "GET":
            r = requests.get(url, params=data, headers=headers)

        else:
            r = requests.request(method, url, headers=headers)

        print(f"{i+1:05d} | {ip} | {attack} | {r.status_code}")

    except Exception as e:
        print("Error:", e)

    time.sleep(random.uniform(0.5, 1.5))


print("\nSimulation Finished.")