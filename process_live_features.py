import pandas as pd
import joblib
import numpy as np

# Load live extracted features
live_df = pd.read_csv("data/live_features.csv")
print(f"📦 Loaded raw features: {live_df.shape}")

# ✅ Keep only the columns that exist in your reduced training model
feature_cols = ['src_port', 'dst_port', 'packet_length', 'protocol',
                'inter_arrival_time', 'tcp_flags']

# Drop rows with NaN or missing values (optional)
live_df = live_df[feature_cols].dropna()

# Load new reduced scaler and model
scaler = joblib.load("models/reduced_scaler.pkl")
model = joblib.load("models/reduced_model.pkl")

# Scale numeric data
scaled = scaler.transform(live_df)

# Predict
predictions = model.predict(scaled)
live_df['prediction'] = predictions

# Save results
live_df.to_csv("data/live_predictions.csv", index=False)
print("✅ Saved predictions to data/live_predictions.csv")

# Show summary
print("\n🔍 Prediction summary:")
print(live_df['prediction'].value_counts())
