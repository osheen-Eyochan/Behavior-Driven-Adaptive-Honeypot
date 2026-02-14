import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# -----------------------------
# 1️⃣ Load Dataset
# -----------------------------
df = pd.read_csv("honeypot_data.csv")

print("Dataset Loaded")
print("Rows:", len(df))


# -----------------------------
# 2️⃣ Encode Categorical Features
# -----------------------------
le_path = LabelEncoder()
le_method = LabelEncoder()
le_agent = LabelEncoder()
le_attack = LabelEncoder()

df["request_path"] = le_path.fit_transform(df["request_path"])
df["request_method"] = le_method.fit_transform(df["request_method"])
df["user_agent"] = le_agent.fit_transform(df["user_agent"])

# Target column
df["attack_type"] = le_attack.fit_transform(df["attack_type"])


# -----------------------------
# 3️⃣ Select Features (NO RISK SCORE)
# -----------------------------
X = df[[
    "request_path",
    "request_method",
    "user_agent",
    "failed_login_attempts",
    "request_count"
]]

y = df["attack_type"]


# -----------------------------
# 4️⃣ Train-Test Split
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)


# -----------------------------
# 5️⃣ Train Model
# -----------------------------
model = RandomForestClassifier(n_estimators=150, random_state=42)
model.fit(X_train, y_train)


# -----------------------------
# 6️⃣ Evaluate Model
# -----------------------------
y_pred = model.predict(X_test)

print("\nModel Accuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# -----------------------------
# 7️⃣ Save Model
# -----------------------------
joblib.dump(model, "attack_model.pkl")
joblib.dump(le_path, "path_encoder.pkl")
joblib.dump(le_method, "method_encoder.pkl")
joblib.dump(le_agent, "agent_encoder.pkl")
joblib.dump(le_attack, "attack_encoder.pkl")

print("\nModel Saved Successfully")
