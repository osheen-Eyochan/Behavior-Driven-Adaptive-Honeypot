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
# Feature Engineering
# -----------------------------

# Encode request_method
method_encoder = LabelEncoder()
df["request_method"] = method_encoder.fit_transform(df["request_method"])

# Convert user_agent into simple bot/browser feature
df["is_bot"] = df["user_agent"].str.contains(
    "bot|curl|python|scanner|wget", case=False
).astype(int)


# -----------------------------
# Select Features (NO risk_score, NO risk_level)
# -----------------------------
X = df[
    [
        "failed_login_attempts",
        "request_count",
        "request_method",
        "is_bot"
    ]
]

# Target
attack_encoder = LabelEncoder()
y = attack_encoder.fit_transform(df["attack_type"])


# -----------------------------
# Split Data
# -----------------------------
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y  # important for class balance
)


# -----------------------------
# Train Model (balanced)
# -----------------------------
model = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train, y_train)


# -----------------------------
# Evaluate
# -----------------------------
y_pred = model.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)

print("\nImproved Model Accuracy:", accuracy)
print("\nClassification Report:\n")
print(classification_report(y_test, y_pred))


# -----------------------------
# Save Model
# -----------------------------
joblib.dump(model, "attack_model.pkl")
joblib.dump(attack_encoder, "attack_encoder.pkl")
joblib.dump(method_encoder, "method_encoder.pkl")

print("\nImproved Model Saved Successfully")
