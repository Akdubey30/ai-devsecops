import os
import json
import re

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

findings = []

patterns = [
    ("Hardcoded Password", r"(password|passwd|pwd)\s*=\s*['\"].+['\"]", "High"),
    ("Hardcoded API Key", r"(api_key|apikey|secret|token)\s*=\s*['\"].+['\"]", "High"),
    ("SQL Injection Risk", r"execute\s*\(.*\+.*\)", "Critical"),
    ("Command Injection Risk", r"os\.system|subprocess\.call|subprocess\.Popen", "Critical"),
    ("Unsafe Eval", r"\beval\s*\(", "Critical"),
    ("Unsafe Exec", r"\bexec\s*\(", "Critical"),
    ("Debug Mode Enabled", r"debug\s*=\s*True", "Medium"),
    ("Insecure HTTP URL", r"http://", "Medium"),
]

ignore_dirs = {".git", "venv", ".venv", "__pycache__", "node_modules"}

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in ignore_dirs]

    for file in files:
        if file.endswith(".py"):
            path = os.path.join(root, file)

            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    code = f.read()
            except Exception:
                continue

            for title, pattern, severity in patterns:
                if re.search(pattern, code, re.IGNORECASE):
                    findings.append({
                        "tool": "AI Security Engine",
                        "title": title,
                        "severity": severity,
                        "file": path
                    })

risk_score = 0

for finding in findings:
    severity = finding["severity"]

    if severity == "Critical":
        risk_score += 35
    elif severity == "High":
        risk_score += 25
    elif severity == "Medium":
        risk_score += 15
    else:
        risk_score += 5

risk_score = min(risk_score, 100)

if risk_score >= 70:
    decision = "BLOCK_DEPLOYMENT"
elif risk_score >= 35:
    decision = "MANUAL_REVIEW"
else:
    decision = "ALLOW_DEPLOYMENT"

report = {
    "findings": findings,
    "risk_engine": {
        "risk_score": risk_score,
        "decision": decision
    }
}

with open(os.path.join(REPORTS_DIR, "ai_security_report.json"), "w") as f:
    json.dump(report, f, indent=4)

print(json.dumps(report, indent=4))

if decision == "BLOCK_DEPLOYMENT":
    print("Deployment blocked by AI Security Engine")
    exit(1)