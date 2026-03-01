import argparse
from collections import defaultdict
import re
from datetime import datetime

parser = argparse.ArgumentParser(description="FinWatch SOC Monitoring System")
parser.add_argument("--logfile", type=str, default="auth_logs.txt", help="Path to log file")
args = parser.parse_args()

print("\nFinWatch SOC Monitoring System v3.0 Starting...\n")

failed_attempts = defaultdict(int)
after_hours_logins = []
phishing_attempts = []
incidents = []

BUSINESS_START = 9
BUSINESS_END = 18

with open(args.logfile, "r") as file:
    logs = file.readlines()

for line in logs:
    ip_match = re.search(r"IP:(\d+\.\d+\.\d+\.\d+)", line)
    if not ip_match:
        continue
    ip = ip_match.group(1)

    time_match = re.search(r"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if not time_match:
        continue
    timestamp = datetime.strptime(time_match.group(1), "%Y-%m-%d %H:%M:%S")
    hour = timestamp.hour

    if "LOGIN_FAILED" in line:
        failed_attempts[ip] += 1

    if "LOGIN_SUCCESS" in line and (hour < BUSINESS_START or hour > BUSINESS_END):
        after_hours_logins.append((ip, timestamp))

    if "PHISHING_LINK_CLICKED" in line:
        phishing_attempts.append((ip, timestamp))

incident_id = 1

for ip, count in failed_attempts.items():
    if count >= 5:
        incidents.append({
            "id": f"IR-2026-{incident_id:03}",
            "type": "Brute Force Attack",
            "ip": ip,
            "severity": "HIGH",
            "details": f"{count} failed login attempts"
        })
        incident_id += 1

for ip, timestamp in after_hours_logins:
    incidents.append({
        "id": f"IR-2026-{incident_id:03}",
        "type": "Suspicious After-Hours Login",
        "ip": ip,
        "severity": "MEDIUM",
        "details": f"Login at {timestamp}"
    })
    incident_id += 1

for ip, timestamp in phishing_attempts:
    incidents.append({
        "id": f"IR-2026-{incident_id:03}",
        "type": "Phishing Activity Detected",
        "ip": ip,
        "severity": "HIGH",
        "details": f"User clicked phishing link at {timestamp}"
    })
    incident_id += 1

print("----- SOC Incident Report -----\n")

for incident in incidents:
    print(f"{incident['id']} | {incident['type']} | {incident['severity']} | {incident['ip']}")

with open("incident_report.txt", "w") as report:
    for incident in incidents:
        report.write(f"{incident}\n")

print("\nIncident report exported.")