import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
import joblib


# -----------------------------
# Load Dataset
# -----------------------------
df = pd.read_csv("honeypot_ml.csv")

print("Dataset Loaded")
print("Rows:", len(df))


# -----------------------------
# Select Features & Target
# -----------------------------

X = df[
    [
        "failed_login_attempts",
        "request_count",
        "risk_score",
        "risk_level"
    ]
]

y = df["attack_type"]


# -----------------------------
# Encode Categorical Data
# -----------------------------

le_risk = LabelEncoder()
X["risk_level"] = le_risk.fit_transform(X["risk_level"])

le_attack = LabelEncoder()
y = le_attack.fit_transform(y)


# -----------------------------
# Split Data
# -----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42
)


# -----------------------------
# Train Model
# -----------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)


# -----------------------------
# Test Model
# -----------------------------

y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nModel Accuracy:", accuracy)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# -----------------------------
# Save Model
# -----------------------------

joblib.dump(model, "attack_model.pkl")
joblib.dump(le_risk, "risk_encoder.pkl")
joblib.dump(le_attack, "attack_encoder.pkl")

print("\nModel Saved Successfully")
