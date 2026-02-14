import pandas as pd

# Read TAB separated file
df = pd.read_csv("honeypot_data.csv", sep="\t")

print("Number of columns:", len(df.columns))
print("Column names:")
print(df.columns)

print("\nFirst 5 rows:")
print(df.head())