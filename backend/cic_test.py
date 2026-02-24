import pandas as pd
import glob

# Read all CSV files inside dataset folder
files = glob.glob("dataset/*.csv")

print("Files found:", len(files))

# Show file names
for f in files:
    print(f)

# Load and combine
df_list = []

for f in files:
    df = pd.read_csv(f, low_memory=False)
    df_list.append(df)

# Combine all files
data = pd.concat(df_list, ignore_index=True)

# 🔥 CLEAN COLUMN NAMES
data.columns = data.columns.str.strip()

print("\n✅ Dataset Loaded Successfully")
print("Shape:", data.shape)

print("\nColumn Names:")
print(data.columns)

print("\nUnique Labels:")
print(data['Label'].unique())
