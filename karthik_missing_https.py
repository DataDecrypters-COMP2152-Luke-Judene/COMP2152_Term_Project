# Author: Karthik
# Vulnerability: Missing HTTPS / Insecure Communication
# Target: blog.0x10.cloud, api.0x10.cloud, login.0x10.cloud, vpn.0x10.cloud

import urllib.request
import time

targets = [
    "http://blog.0x10.cloud",
    "http://api.0x10.cloud",
    "http://login.0x10.cloud",
    "http://vpn.0x10.cloud"
]

for t in targets:
    try:
        response = urllib.request.urlopen(t)
        final_url = response.url

        print(f"\nChecking: {t}")
        print(f"Final URL: {final_url}")

        if final_url.startswith("http://"):
            print("[!] VULNERABILITY FOUND")
            print("Reason: No HTTPS (data not encrypted)")
        else:
            print("[OK] Uses HTTPS")

        time.sleep(0.2)

    except Exception as e:
        print(f"{t} → ERROR: {e}")