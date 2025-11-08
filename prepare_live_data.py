import pandas as pd
import numpy as np

# Load raw live data
df = pd.read_csv("data/live_capture.csv")

# Convert Protocol to numeric
df['protocol'] = df['Protocol'].astype('category').cat.codes

# Simulate or extract numeric features (example logic)
df['src_port'] = np.random.randint(1024, 65535, size=len(df))
df['dst_port'] = np.random.randint(1024, 65535, size=len(df))
df['packet_length'] = df['Length']
df['inter_arrival_time'] = df['Time'].diff().fillna(0)
df['tcp_flags'] = np.random.randint(0, 64, size=len(df))  # placeholder

# Keep only expected features
df_final = df[['src_port', 'dst_port', 'packet_length', 'protocol', 'inter_arrival_time', 'tcp_flags']]

# Save cleaned data
df_final.to_csv("data/live_cleaned.csv", index=False)
print("✅ Live data cleaned and saved as data/live_cleaned.csv")
