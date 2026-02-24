import pandas as pd
import glob
import joblib

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.metrics import classification_report, confusion_matrix

print("=== Loading CICIDS2017 Dataset ===")

# Load all CSV files from dataset folder
files = glob.glob("backend/dataset/*.csv")

if len(files) == 0:
    print("❌ No CSV files found in dataset folder")
    exit()

df_list = []

for file in files:
    print("Loading:", file)
    df = pd.read_csv(file, low_memory=False)
    df_list.append(df)

# Combine all files into one dataset
data = pd.concat(df_list, ignore_index=True)

print("\n✅ Combined Dataset Shape:", data.shape)


# -----------------------------
# DATA CLEANING
# -----------------------------
print("\n=== Cleaning Data ===")

# Remove infinite values
data.replace([float('inf'), -float('inf')], 0, inplace=True)

# Fill missing values
data.fillna(0, inplace=True)


# -----------------------------
# SEPARATE FEATURES & LABEL
# -----------------------------
print("\n=== Preparing Features ===")

# In CICIDS2017 label column has leading space: " Label"
if " Label" not in data.columns:
    print("❌ Label column not found. Available columns:")
    print(data.columns)
    exit()

X = data.drop(" Label", axis=1)
y = data[" Label"]

print("Number of Features:", X.shape[1])
print("\nAttack Types:")
print(y.value_counts())


# -----------------------------
# ENCODE LABELS
# -----------------------------
print("\n=== Encoding Labels ===")

le = LabelEncoder()
y_encoded = le.fit_transform(y)


# -----------------------------
# TRAIN TEST SPLIT
# -----------------------------
print("\n=== Splitting Data ===")

X_train, X_test, y_train, y_test = train_test_split(
    X, y_encoded, test_size=0.2, random_state=42
)


# -----------------------------
# TRAIN MODEL (Decision Tree)
# -----------------------------
print("\n=== Training Model B (External Model) ===")

model = DecisionTreeClassifier(random_state=42)
model.fit(X_train, y_train)


# -----------------------------
# EVALUATION
# -----------------------------
print("\n=== Evaluating Model ===")

accuracy = model.score(X_test, y_test)
print("\n✅ External Model Accuracy:", accuracy)

y_pred = model.predict(X_test)

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred))


# -----------------------------
# SAVE MODEL
# -----------------------------
joblib.dump(model, "model_external.pkl")
joblib.dump(le, "label_encoder_external.pkl")

print("\n✅ Model saved as model_external.pkl")
print("✅ Label encoder saved as label_encoder_external.pkl")

print("\n🎯 External Model Training Completed")