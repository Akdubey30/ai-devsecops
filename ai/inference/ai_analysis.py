import json
import joblib
from ai.utils.embedding import get_embedding

model = joblib.load("ai/models/codebert_rf_model.pkl")

with open("security-reports/codeql-report.json") as f:
    codeql = json.load(f)

risk = {"HIGH":0, "MEDIUM":0, "LOW":0}

for r in codeql.get("runs", [])[0].get("results", []):
    text = r.get("message", {}).get("text", "")
    pred = model.predict([get_embedding(text)])[0]
    risk[pred] += 1

print("AI Risk:", risk)

if risk["HIGH"] > 2:
    print("BLOCK DEPLOYMENT")
    exit(1)