import pandas as pd
import numpy as np

np.random.seed(42)
rows = 2000  # number of samples

df = pd.DataFrame({
    "src_port": np.random.randint(1000, 9000, rows),
    "dst_port": np.random.choice([21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 8080], rows),
    "packet_length": np.random.randint(64, 1500, rows),
    "protocol": np.random.choice([6, 17], rows),  # 6 = TCP, 17 = UDP
    "inter_arrival_time": np.random.random(rows) * 0.05,
    "tcp_flags": np.random.choice([0, 2, 16, 18, 24], rows),
    "label": np.random.choice(["normal", "attack"], rows, p=[0.7, 0.3])
})

df.to_csv("data/train.csv", index=False)
print("✅ Fake dataset created and saved to data/train.csv")
print("📦 Shape:", df.shape)
print(df.head())
