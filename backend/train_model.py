import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score


# -----------------------------
# 1️⃣ Load Dataset
# -----------------------------
df = pd.read_csv(r"C:\Users\USER\OneDrive\Desktop\dataset.csv")

print("Dataset Loaded")
print("Rows:", len(df))

print("\nAttack Type Distribution:\n")
print(df["attack_type"].value_counts())


# -----------------------------
# 2️⃣ Target Encoding
# -----------------------------
le_attack = LabelEncoder()
df["attack_type"] = le_attack.fit_transform(df["attack_type"])


# -----------------------------
# 3️⃣ Features (IMPORTANT CHANGE)
# -----------------------------
X = df[[
    "request_count",
    "failed_login_attempts",
    "payload_size",
    "param_count",
    "keyword_count",
    "request_interval",
    "same_user_attempts"
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
joblib.dump(le_attack, "attack_encoder.pkl")



print("\nModel Saved Successfully")