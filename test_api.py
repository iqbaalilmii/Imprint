import requests
import json
import time
import sys

BASE_URL = "http://127.0.0.1:8000"

# Check if server is running
try:
    requests.get(f"{BASE_URL}/docs", timeout=2)
except Exception:
    print(f"Error: FastAPI server is not running on {BASE_URL}. Start it first!")
    sys.exit(1)

print("--- 1. POST /api/cases ---")
payload = {
    "case_name": "Test Case Dump",
    "analyst_name": "Antigravity",
    "dump_path": "D:\\Hackathon\\machinelearning\\dump.raw"
}
r = requests.post(f"{BASE_URL}/api/cases", json=payload)
print(f"Status Code: {r.status_code}")
print(f"Response: {json.dumps(r.json(), indent=4)}")
case_id = r.json().get("case_id")

print(f"\n--- 2. POST /api/cases/{case_id}/analyze ---")
r_analyze = requests.post(f"{BASE_URL}/api/cases/{case_id}/analyze")
print(f"Status Code: {r_analyze.status_code}")
print(f"Response: {json.dumps(r_analyze.json(), indent=4)}")

print(f"\n--- 3. Polling /api/cases/{case_id}/status ---")
for i in range(5):
    r_status = requests.get(f"{BASE_URL}/api/cases/{case_id}/status")
    print(f"Poll #{i+1}: Status: {r_status.json()}")
    time.sleep(3)
