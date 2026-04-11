import os

dataset_path = "."

files_path = os.path.join(dataset_path, "suspicious_files")
registry_path = os.path.join(dataset_path, "registry", "run_keys.txt")
log_path = os.path.join(dataset_path, "logs", "process_log.txt")

alerts = 0
files_analysed = 0

print("SOC FORENSIC INVESTIGATION STARTED")
print("-----------------------------------")

# Task 1 — Analyse Files
print("\n[1] Analysing Files")

for file in os.listdir(files_path):

    files_analysed += 1
    filepath = os.path.join(files_path, file)

    size = os.path.getsize(filepath)

    print("File:", file)
    print("Size:", size, "bytes")

    if file.endswith(".exe"):
        print("ALERT: Executable file detected")
        alerts += 1


# Task 2 — Detect Persistence
print("\n[2] Checking Registry Persistence")

with open(registry_path) as f:

    for line in f:

        print(line.strip())

        if "AppData" in line or "Temp" in line:
            print("ALERT: Suspicious persistence detected")
            alerts += 1


# Task 3 — Analyse Execution Logs
print("\n[3] Analysing Process Logs")

with open(log_path) as f:

    logs = f.read()
    print(logs)

    if "evil.exe executed" in logs:
        print("ALERT: Malware execution detected")
        alerts += 1


# Task 4 — Generate Report
print("\n[4] Generating SOC Report")

if alerts >= 3:
    risk = "HIGH"
elif alerts >= 1:
    risk = "MEDIUM"
else:
    risk = "LOW"

report = f"""
SOC FORENSIC INVESTIGATION REPORT
---------------------------------

Files analysed: {files_analysed}
Alerts detected: {alerts}
Risk level: {risk}
"""

print(report)

with open("forensic_report.txt", "w") as f:
    f.write(report)