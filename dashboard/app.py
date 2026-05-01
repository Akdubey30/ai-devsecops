import os
import json
import re
import joblib
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="AI DevSecOps Dashboard",
    page_icon="🛡️",
    layout="wide"
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

REPORTS_DIR = os.path.join(BASE_DIR, "reports")
MODEL_PATH = os.path.join(BASE_DIR, "ai", "models", "codebert_rf_model.pkl")

CODEQL_PATH = os.path.join(REPORTS_DIR, "codeql_report.json")
TRIVY_PATH = os.path.join(REPORTS_DIR, "trivy_report.json")
AI_REPORT_PATH = os.path.join(REPORTS_DIR, "ai_security_report.json")

os.makedirs(REPORTS_DIR, exist_ok=True)


def safe_load_json(path, default):
    if not os.path.exists(path) or os.path.getsize(path) == 0:
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def safe_save_json(path, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def normalize_codeql(data):
    issues = []

    if isinstance(data, dict) and "runs" in data:
        for run in data.get("runs", []):
            rules = {
                rule.get("id", ""): rule
                for tool in [run.get("tool", {})]
                for driver in [tool.get("driver", {})]
                for rule in driver.get("rules", [])
            }

            for result in run.get("results", []):
                rule_id = result.get("ruleId", "Unknown")
                rule = rules.get(rule_id, {})
                severity = rule.get("properties", {}).get("security-severity", "Medium")

                issues.append({
                    "Tool": "CodeQL",
                    "Title": result.get("message", {}).get("text", rule_id),
                    "Severity": str(severity),
                    "File": result.get("locations", [{}])[0]
                        .get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri", "Unknown"),
                    "Line": result.get("locations", [{}])[0]
                        .get("physicalLocation", {})
                        .get("region", {})
                        .get("startLine", "-")
                })

    elif isinstance(data, list):
        for item in data:
            issues.append({
                "Tool": "CodeQL",
                "Title": item.get("title", item.get("message", "CodeQL issue")),
                "Severity": item.get("severity", "Medium"),
                "File": item.get("file", "Unknown"),
                "Line": item.get("line", "-")
            })

    return issues


def normalize_trivy(data):
    issues = []

    if isinstance(data, dict):
        for result in data.get("Results", []):
            target = result.get("Target", "Unknown")
            for vuln in result.get("Vulnerabilities", []) or []:
                issues.append({
                    "Tool": "Trivy",
                    "Title": vuln.get("Title", vuln.get("VulnerabilityID", "Vulnerability")),
                    "Severity": vuln.get("Severity", "Medium"),
                    "File": target,
                    "Line": "-",
                    "Package": vuln.get("PkgName", "-"),
                    "Installed Version": vuln.get("InstalledVersion", "-"),
                    "Fixed Version": vuln.get("FixedVersion", "-")
                })

    elif isinstance(data, list):
        for item in data:
            issues.append({
                "Tool": "Trivy",
                "Title": item.get("title", item.get("message", "Trivy vulnerability")),
                "Severity": item.get("severity", "Medium"),
                "File": item.get("file", "Unknown"),
                "Line": "-"
            })

    return issues


def severity_score(sev):
    sev = str(sev).lower()

    try:
        value = float(sev)
        if value >= 9:
            return "Critical"
        elif value >= 7:
            return "High"
        elif value >= 4:
            return "Medium"
        else:
            return "Low"
    except:
        pass

    if "critical" in sev:
        return "Critical"
    if "high" in sev:
        return "High"
    if "medium" in sev or "warning" in sev:
        return "Medium"
    if "low" in sev or "note" in sev:
        return "Low"

    return "Medium"


def ai_level_1_static(code):
    findings = []

    patterns = [
        ("Hardcoded Password", r"(password|passwd|pwd)\s*=\s*['\"].+['\"]", "High"),
        ("Hardcoded API Key", r"(api_key|apikey|secret|token)\s*=\s*['\"].+['\"]", "High"),
        ("SQL Injection Risk", r"execute\s*\(.*\+.*\)", "Critical"),
        ("Command Injection Risk", r"os\.system|subprocess\.call|subprocess\.Popen", "Critical"),
        ("Unsafe Eval", r"\beval\s*\(", "Critical"),
        ("Unsafe Exec", r"\bexec\s*\(", "Critical"),
        ("Debug Mode Enabled", r"debug\s*=\s*True", "Medium"),
        ("Insecure HTTP", r"http://", "Medium"),
        ("Pickle Usage", r"pickle\.load|joblib\.load", "Medium"),
    ]

    for name, pattern, severity in patterns:
        if re.search(pattern, code, re.IGNORECASE):
            findings.append({
                "Level": "Level 1 - Static AI",
                "Issue": name,
                "Severity": severity,
                "Recommendation": "Avoid insecure pattern and use safer validated alternatives."
            })

    return findings


def ai_level_2_context(code):
    findings = []

    if "input(" in code and ("execute(" in code or "os.system" in code):
        findings.append({
            "Level": "Level 2 - Context AI",
            "Issue": "User Input Reaches Sensitive Function",
            "Severity": "Critical",
            "Recommendation": "Sanitize input and avoid direct execution."
        })

    if "flask" in code.lower() and "debug=True" in code.replace(" ", ""):
        findings.append({
            "Level": "Level 2 - Context AI",
            "Issue": "Flask Debug Mode in Web App",
            "Severity": "High",
            "Recommendation": "Disable debug mode before deployment."
        })

    if "requests.get" in code and "verify=False" in code:
        findings.append({
            "Level": "Level 2 - Context AI",
            "Issue": "SSL Verification Disabled",
            "Severity": "High",
            "Recommendation": "Keep SSL verification enabled."
        })

    return findings


def ai_level_3_risk_engine(findings):
    if not findings:
        return {
            "Level": "Level 3 - AI Risk Engine",
            "Risk Score": 5,
            "Risk Status": "Safe",
            "Decision": "Code looks safe for demo-level scan."
        }

    score = 0
    for f in findings:
        sev = severity_score(f["Severity"])
        if sev == "Critical":
            score += 35
        elif sev == "High":
            score += 25
        elif sev == "Medium":
            score += 15
        else:
            score += 5

    score = min(score, 100)

    if score >= 75:
        status = "Critical"
        decision = "Deployment should be blocked."
    elif score >= 50:
        status = "High"
        decision = "Manual security review required."
    elif score >= 25:
        status = "Medium"
        decision = "Fix recommended before production."
    else:
        status = "Low"
        decision = "Low risk detected."

    return {
        "Level": "Level 3 - AI Risk Engine",
        "Risk Score": score,
        "Risk Status": status,
        "Decision": decision
    }


def analyze_code_with_three_level_ai(code):
    level1 = ai_level_1_static(code)
    level2 = ai_level_2_context(code)
    all_findings = level1 + level2
    level3 = ai_level_3_risk_engine(all_findings)
    return all_findings, level3


def load_model():
    if not os.path.exists(MODEL_PATH):
        return None

    try:
        return joblib.load(MODEL_PATH)
    except Exception:
        return None


st.markdown("""
<style>
.main {
    background-color: #0e1117;
}
.metric-card {
    padding: 20px;
    border-radius: 16px;
    background: #161b22;
    border: 1px solid #30363d;
}
.big-text {
    font-size: 30px;
    font-weight: 700;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ AI DevSecOps Dashboard")
st.caption("CodeQL + Trivy + 3-Level AI Security Engine")

model = load_model()

if model:
    st.success("✅ AI Model Loaded")
else:
    st.warning("⚠️ Model not found/corrupt. Dashboard is running with rule-based 3-Level AI Engine.")

codeql_raw = safe_load_json(CODEQL_PATH, [])
trivy_raw = safe_load_json(TRIVY_PATH, [])
ai_report_raw = safe_load_json(AI_REPORT_PATH, [])

codeql_issues = normalize_codeql(codeql_raw)
trivy_issues = normalize_trivy(trivy_raw)

all_security_issues = codeql_issues + trivy_issues

df = pd.DataFrame(all_security_issues)

if not df.empty:
    df["Severity"] = df["Severity"].apply(severity_score)

critical = len(df[df["Severity"] == "Critical"]) if not df.empty else 0
high = len(df[df["Severity"] == "High"]) if not df.empty else 0
medium = len(df[df["Severity"] == "Medium"]) if not df.empty else 0
low = len(df[df["Severity"] == "Low"]) if not df.empty else 0

c1, c2, c3, c4 = st.columns(4)

c1.metric("🚨 Critical", critical)
c2.metric("🔥 High", high)
c3.metric("⚠️ Medium", medium)
c4.metric("✅ Low", low)

st.divider()

tab1, tab2, tab3, tab4 = st.tabs([
    "📊 Overview",
    "🔍 Reports",
    "🤖 3-Level AI Analyzer",
    "🚀 Deployment Decision"
])

with tab1:
    st.subheader("Security Overview")

    if df.empty:
        st.info("No CodeQL/Trivy issues found yet. Run pipeline or paste code in AI analyzer.")
    else:
        left, right = st.columns(2)

        with left:
            sev_count = df["Severity"].value_counts()
            st.bar_chart(sev_count)

        with right:
            tool_count = df["Tool"].value_counts()
            st.bar_chart(tool_count)

        st.subheader("All Security Issues")
        st.dataframe(df, use_container_width=True)

with tab2:
    st.subheader("CodeQL Report")
    if codeql_issues:
        st.dataframe(pd.DataFrame(codeql_issues), use_container_width=True)
    else:
        st.info("No CodeQL report data found.")

    st.subheader("Trivy Report")
    if trivy_issues:
        st.dataframe(pd.DataFrame(trivy_issues), use_container_width=True)
    else:
        st.info("No Trivy report data found.")

    with st.expander("Raw CodeQL JSON"):
        st.json(codeql_raw)

    with st.expander("Raw Trivy JSON"):
        st.json(trivy_raw)

with tab3:
    st.subheader("🤖 3-Level AI Security Analyzer")

    st.markdown("""
    **Level 1:** Static vulnerability pattern detection  
    **Level 2:** Context-aware security analysis  
    **Level 3:** AI risk scoring and deployment decision  
    """)

    sample_code = """import os

password = "admin123"
user_input = input("Enter command: ")
os.system(user_input)

debug = True
"""

    user_code = st.text_area(
        "Paste code here",
        value=sample_code,
        height=250
    )

    if st.button("Analyze Code"):
        findings, risk = analyze_code_with_three_level_ai(user_code)

        st.subheader("Level 1 + Level 2 Findings")

        if findings:
            findings_df = pd.DataFrame(findings)
            st.dataframe(findings_df, use_container_width=True)

            sev_df = findings_df["Severity"].apply(severity_score).value_counts()
            st.bar_chart(sev_df)
        else:
            st.success("No risky pattern detected.")

        st.subheader("Level 3 AI Risk Engine")

        score = risk["Risk Score"]
        status = risk["Risk Status"]

        st.metric("AI Risk Score", f"{score}/100")
        st.metric("Risk Status", status)

        if status in ["Critical", "High"]:
            st.error(risk["Decision"])
        elif status == "Medium":
            st.warning(risk["Decision"])
        else:
            st.success(risk["Decision"])

        final_report = {
            "findings": findings,
            "risk_engine": risk
        }

        safe_save_json(AI_REPORT_PATH, final_report)
        st.success("AI security report saved to reports/ai_security_report.json")

with tab4:
    st.subheader("🚀 Deployment Decision Engine")

    total_risk = critical * 40 + high * 25 + medium * 10 + low * 3
    total_risk = min(total_risk, 100)

    st.metric("Pipeline Risk Score", f"{total_risk}/100")

    if total_risk >= 70:
        st.error("❌ Deployment Blocked")
        st.write("Critical/high vulnerabilities detected. Fix security issues before deployment.")
    elif total_risk >= 35:
        st.warning("⚠️ Deployment Needs Manual Review")
        st.write("Some medium/high risks exist. Manual approval recommended.")
    else:
        st.success("✅ Deployment Approved")
        st.write("No major security blockers detected.")

    st.progress(total_risk / 100)