import os
import pickle
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report
from lightgbm import LGBMClassifier

print("Loading dataset...")
df = pd.read_csv("combined_dataset.csv")


df.columns = df.columns.str.strip()

df.replace([np.inf, -np.inf], np.nan, inplace=True)

# Fill only numeric columns
numeric_cols = df.select_dtypes(include=[np.number]).columns
df[numeric_cols] = df[numeric_cols].fillna(0)
# Binary label
df["Label"] = df["Label"].apply(lambda x: 0 if x == "BENIGN" else 1)

# Select REAL flow features
selected_features = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Std"
]

X = df[selected_features]
y = df["Label"]

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

model = LGBMClassifier(n_estimators=200, random_state=42)
model.fit(X_train_scaled, y_train)

print(classification_report(y_test, model.predict(X_test_scaled)))

os.makedirs("models", exist_ok=True)

with open("models/model.pkl", "wb") as f:
    pickle.dump(model, f)

with open("models/scaler.pkl", "wb") as f:
    pickle.dump(scaler, f)

with open("models/features.pkl", "wb") as f:
    pickle.dump(selected_features, f)

print("Training complete and saved.")