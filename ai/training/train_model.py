import json
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from ai.utils.embedding import get_embedding

print("🚀 Loading dataset...")

with open("ai/dataset/code_security_dataset.json") as f:
    data = json.load(f)

X = []
y = []

print(f"📊 Total samples: {len(data)}")

for i, item in enumerate(data):
    try:
        emb = get_embedding(item["code"])
        X.append(emb)
        y.append(item["label"])

        if i % 10 == 0:
            print(f"⚡ Processed {i}/{len(data)}")

    except Exception as e:
        print(f"❌ Error at {i}: {e}")

print("🧠 Converting to numpy...")
X = np.array(X)
y = np.array(y)

print("📚 Training model...")
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X, y)

print("💾 Saving model...")
joblib.dump(model, "ai/models/codebert_rf_model.pkl")

print("✅ Model trained successfully")