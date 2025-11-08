import pandas as pd

print("🚀 Loading merged dataset...")
df = pd.read_parquet("data/merged_dataset.parquet")

print("📊 Original shape:", df.shape)

# Drop useless or redundant columns if they exist
drop_cols = [col for col in df.columns if 'Timestamp' in col or 'Flow ID' in col or 'Src IP' in col or 'Dst IP' in col]
df.drop(columns=[c for c in drop_cols if c in df.columns], inplace=True, errors='ignore')

# Drop rows with missing or infinite values
df.replace([float('inf'), float('-inf')], pd.NA, inplace=True)
df.dropna(inplace=True)

print("🧹 Cleaned shape:", df.shape)

# Encode categorical columns (e.g. Label)
if 'Label' in df.columns:
    df['Label'] = df['Label'].astype('category').cat.codes

print("✅ Encoded labels. Unique labels:", df['Label'].unique())

# Save cleaned dataset
df.to_parquet("data/cleaned_dataset.parquet")
print("💾 Saved cleaned dataset to data/cleaned_dataset.parquet")
