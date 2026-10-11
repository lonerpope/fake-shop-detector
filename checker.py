import socket, whois
from datetime import datetime
import requests

domain = input("Enter domain (ex: jumia.co.ke): ").strip()
score = 100

print(f"\n--- Checking {domain} ---")

# 1. IP
try:
    ip = socket.gethostbyname(domain)
    print(f"[+] IP: {ip}")
except:
    print("[-] No IP found - Score -40")
    score -= 40

# 2. Age
try:
    info = whois.whois(domain)
    created = info.creation_date
    if isinstance(created, list):
        created = created[0]
    age = datetime.now().year - created.year if created else 0
    print(f"[+] Created: {created} ({age} years old)")
    if age < 1:
        print(" -> SUSPICIOUS: Very new domain! -40")
        score -= 40
    elif age < 2:
        print(" -> CAUTION: Young domain -20")
        score -= 20
    else:
        print(" -> SAFE: Old domain")
except Exception as e:
    print(f"[-] Whois error: {e} -20")
    score -= 20

# 3. HTTPS
try:
    r = requests.get(f"https://{domain}", timeout=5)
    print(f"[+] HTTPS: Yes (Status {r.status_code})")
except:
    print("[-] HTTPS: No / Failed -20")
    score -= 20

# Final score
print(f"\n=== SCORE: {score}/100 ===")
if score >= 80:
    print("Result: LIKELY LEGIT")
elif score >= 50:
    print("Result: BE CAUTIOUS")
else:
    print("Result: LIKELY SCAM")
