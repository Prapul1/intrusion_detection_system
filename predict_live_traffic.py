import pandas as pd
import joblib
import os

# Load the live traffic data
live_data_path = "data/live_capture.csv"
print("🚀 Loading live capture data...")
df = pd.read_csv(live_data_path)

print(f"✅ Loaded {df.shape[0]} packets from live capture")

# Preprocessing: Drop non-numeric or irrelevant columns
# (since your model was trained on numeric KDD features)
df_clean = df.drop(columns=["No", "Time", "Info"], errors="ignore")

# You might have to encode Protocol or IPs if they exist (simple numeric placeholder)
from sklearn.preprocessing import LabelEncoder
le = LabelEncoder()
for col in df_clean.columns:
    if df_clean[col].dtype == 'object':
        df_clean[col] = le.fit_transform(df_clean[col].astype(str))

# Load your best trained model
best_model_path = os.path.join("models", "lightgbm.pkl")  # Change to your best model if different
model = joblib.load(best_model_path)
print("🧠 Loaded model:", best_model_path)

# Predict
predictions = model.predict(df_clean)

# Mapping (same as before)
attack_category_mapping = {
    0: "Normal",
    1: "DoS", 2: "DoS", 3: "DoS", 4: "DoS", 5: "DoS", 6: "DoS", 7: "DoS", 8: "DoS", 9: "DoS",
    10: "Probe", 11: "Probe", 12: "Probe", 13: "Probe",
    14: "R2L", 15: "R2L", 16: "R2L", 17: "R2L",
    18: "U2R", 19: "U2R", 20: "U2R", 21: "U2R"
}

# Convert numeric predictions to categories
pred_labels = [attack_category_mapping.get(i, "Unknown") for i in predictions]

# Combine with original data
df["Predicted_Category"] = pred_labels

# Save results
output_file = "results/live_prediction_results.csv"
os.makedirs("results", exist_ok=True)
df.to_csv(output_file, index=False)

print(f"✅ Predictions complete! Results saved at: {output_file}")
print(df[["Source", "Destination", "Protocol", "Predicted_Category"]].head(10))
