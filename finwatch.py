from collections import defaultdict
import re
from datetime import datetime

print("\nFinWatch SOC Monitoring System v2.0 Starting...\n")

failed_attempts = defaultdict(int)
after_hours_logins = []
phishing_attempts = []

BUSINESS_START = 9
BUSINESS_END = 18

# Incident storage
incidents = []

with open("auth_logs.txt", "r") as file:
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

    # Count failed attempts
    if "LOGIN_FAILED" in line:
        failed_attempts[ip] += 1

    # After-hours success
    if "LOGIN_SUCCESS" in line and (hour < BUSINESS_START or hour > BUSINESS_END):
        after_hours_logins.append((ip, timestamp))

    # Phishing simulation
    if "PHISHING_LINK_CLICKED" in line:
        phishing_attempts.append((ip, timestamp))

incident_id = 1

# Brute Force Detection
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

# After Hours Detection
for ip, timestamp in after_hours_logins:
    incidents.append({
        "id": f"IR-2026-{incident_id:03}",
        "type": "Suspicious After-Hours Login",
        "ip": ip,
        "severity": "MEDIUM",
        "details": f"Login at {timestamp}"
    })
    incident_id += 1

# Phishing Detection
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
    print(f"Incident ID: {incident['id']}")
    print(f"Threat Type: {incident['type']}")
    print(f"Source IP: {incident['ip']}")
    print(f"Severity: {incident['severity']}")
    print(f"Details: {incident['details']}")
    print("-" * 40)


# Export report to file
with open("incident_report.txt", "w") as report:
    for incident in incidents:
        report.write(f"{incident['id']} | {incident['type']} | {incident['ip']} | {incident['severity']} | {incident['details']}\n")

print("\nIncident report exported to incident_report.txt")