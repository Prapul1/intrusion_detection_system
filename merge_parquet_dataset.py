import pandas as pd
import glob
import os

# Define the folder containing parquet files
DATA_DIR = "data"

print(f"🚀 Merging all Parquet files in: {DATA_DIR}")

# Find all parquet files
files = glob.glob(os.path.join(DATA_DIR, "*.parquet"))

# Check if any parquet files exist
if not files:
    raise FileNotFoundError("❌ No .parquet files found in the data folder.")

# Read and merge
dfs = []
for f in files:
    print(f"📦 Reading {f} ...")
    df_part = pd.read_parquet(f)
    dfs.append(df_part)

# Concatenate all dataframes
df = pd.concat(dfs, ignore_index=True)

print(f"✅ Merged {len(files)} parquet files. Total rows: {len(df):,}")

# Ensure output folder exists
os.makedirs(DATA_DIR, exist_ok=True)

# Save merged dataset
output_path = os.path.join(DATA_DIR, "merged_dataset.parquet")
df.to_parquet(output_path)

print(f"💾 Saved merged dataset to {output_path}")
