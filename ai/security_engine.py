import os
import json
import re
from datetime import datetime

REPORTS_DIR = "reports"
AI_REPORT_PATH = os.path.join(REPORTS_DIR, "ai_security_report.json")

os.makedirs(REPORTS_DIR, exist_ok=True)

findings = []

patterns = [
    ("Hardcoded Password", r"(password|passwd|pwd)\s*=\s*['\"].+['\"]", "High"),
    ("Hardcoded API Key / Secret / Token", r"(api_key|apikey|secret|token)\s*=\s*['\"].+['\"]", "High"),
    ("SQL Injection Risk", r"execute\s*\(.*\+.*\)", "Critical"),
    ("Command Injection Risk", r"os\.system\s*\(|subprocess\.call\s*\(|subprocess\.Popen\s*\(", "Critical"),
    ("Unsafe Eval Usage", r"\beval\s*\(", "Critical"),
    ("Unsafe Exec Usage", r"\bexec\s*\(", "Critical"),
    ("Debug Mode Enabled", r"debug\s*=\s*True", "Medium"),
    ("Insecure HTTP URL", r"http://", "Medium"),
    ("Unsafe Pickle Loading", r"pickle\.load\s*\(|joblib\.load\s*\(", "Medium"),
]

ignore_dirs = {
    ".git",
    "venv",
    ".venv",
    "__pycache__",
    "node_modules",
    ".github",
}

scan_extensions = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".yml",
    ".yaml",
    ".json",
    ".env",
    ".txt",
}


def severity_points(severity):
    severity = severity.lower()

    if severity == "critical":
        return 35
    if severity == "high":
        return 25
    if severity == "medium":
        return 15
    if severity == "low":
        return 5

    return 5


def get_decision(score):
    if score >= 70:
        return "BLOCK_DEPLOYMENT"
    elif score >= 35:
        return "MANUAL_REVIEW"
    else:
        return "ALLOW_DEPLOYMENT"


def read_file_safely(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def scan_file(path):
    code = read_file_safely(path)

    if not code:
        return

    for title, pattern, severity in patterns:
        matches = list(re.finditer(pattern, code, re.IGNORECASE))

        for match in matches:
            line_no = code[:match.start()].count("\n") + 1

            findings.append({
                "tool": "AI Security Engine",
                "title": title,
                "severity": severity,
                "file": path,
                "line": line_no,
                "level": "Level 1 - Static Pattern Detection",
                "recommendation": get_recommendation(title)
            })

    context_analysis(path, code)


def context_analysis(path, code):
    compact_code = code.replace(" ", "").replace("\n", "")

    if "input(" in code and "os.system(" in compact_code:
        findings.append({
            "tool": "AI Security Engine",
            "title": "User Input Reaches System Command",
            "severity": "Critical",
            "file": path,
            "line": "-",
            "level": "Level 2 - Context Aware Analysis",
            "recommendation": "Never pass raw user input into system commands. Validate input or avoid shell execution."
        })

    if "input(" in code and ("execute(" in code or "cursor.execute(" in code):
        findings.append({
            "tool": "AI Security Engine",
            "title": "User Input Reaches Database Query",
            "severity": "Critical",
            "file": path,
            "line": "-",
            "level": "Level 2 - Context Aware Analysis",
            "recommendation": "Use parameterized queries instead of string concatenation."
        })

    if "requests.get" in code and "verify=False" in compact_code:
        findings.append({
            "tool": "AI Security Engine",
            "title": "SSL Verification Disabled",
            "severity": "High",
            "file": path,
            "line": "-",
            "level": "Level 2 - Context Aware Analysis",
            "recommendation": "Keep SSL verification enabled in production."
        })


def get_recommendation(title):
    title = title.lower()

    if "password" in title:
        return "Remove hardcoded password and use environment variables or secret manager."
    if "api" in title or "secret" in title or "token" in title:
        return "Store secrets in GitHub Secrets, environment variables, or vault systems."
    if "sql" in title:
        return "Use prepared statements or parameterized queries."
    if "command" in title:
        return "Avoid shell execution with user-controlled input."
    if "eval" in title or "exec" in title:
        return "Avoid eval/exec because they can execute arbitrary code."
    if "debug" in title:
        return "Disable debug mode before production deployment."
    if "http" in title:
        return "Use HTTPS instead of HTTP."
    if "pickle" in title:
        return "Load model files only from trusted locations."

    return "Review and fix this security issue before production."


for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in ignore_dirs]

    for file in files:
        ext = os.path.splitext(file)[1].lower()

        if ext in scan_extensions:
            path = os.path.join(root, file)
            scan_file(path)


risk_score = 0

for finding in findings:
    risk_score += severity_points(finding.get("severity", "Low"))

risk_score = min(risk_score, 100)
decision = get_decision(risk_score)

if decision == "BLOCK_DEPLOYMENT":
    status = "Critical Risk"
elif decision == "MANUAL_REVIEW":
    status = "Needs Manual Review"
else:
    status = "Safe to Deploy"

report = {
    "generated_at": datetime.utcnow().isoformat() + "Z",
    "tool": "AI Security Engine",
    "summary": {
        "total_findings": len(findings),
        "critical": len([f for f in findings if f["severity"] == "Critical"]),
        "high": len([f for f in findings if f["severity"] == "High"]),
        "medium": len([f for f in findings if f["severity"] == "Medium"]),
        "low": len([f for f in findings if f["severity"] == "Low"]),
    },
    "findings": findings,
    "risk_engine": {
        "risk_score": risk_score,
        "risk_status": status,
        "decision": decision,
        "mode": "DEMO_MODE",
        "note": "Pipeline will continue so reports can be generated. Deployment decision is still shown in dashboard."
    }
}

with open(AI_REPORT_PATH, "w", encoding="utf-8") as f:
    json.dump(report, f, indent=4)

print(json.dumps(report, indent=4))

print("\nAI Security Engine completed.")
print(f"Risk Score: {risk_score}/100")
print(f"Decision: {decision}")

# IMPORTANT:
# Demo mode me pipeline fail nahi hogi.
# Strict production mode me yaha exit(1) kar sakte hain.
exit(0)