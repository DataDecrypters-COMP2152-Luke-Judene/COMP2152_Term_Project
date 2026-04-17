# Author : Sanyoung Yoon
# Name of Vulnerability : Information Disclosure
# Target : api.0x10.cloud

import urllib.request
import json

url = "http://api.0x10.cloud"

try:
    response = urllib.request.urlopen(url, timeout=5)
    content = response.read().decode()
    data = json.loads(content)

    service = data.get("service", "Not found")
    version = data.get("version", "Not found")
    endpoints = data.get("endpoints", [])

    print("Service:", service)
    print("Version:", version)
    print("Endpoints:", endpoints)

    if version !="Not found" or len(endpoints) > 0:
        print("\nVULNERABILITY FOUND: Information Disclosure")
        print("\nThe API exposes internal information such as version details and endpoint paths.")
        print("\nAttackers can use this information to understand the system structure and plan further attacks.")
    else:
        print("\nNo sensitive information was found.")

except Exception as e:
    print("Error:", e)