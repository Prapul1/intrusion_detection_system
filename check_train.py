import pandas as pd

df = pd.read_csv("data/train.csv")
print("✅ Shape:", df.shape)
print(df.head().to_string())
