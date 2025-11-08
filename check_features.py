import joblib

# Load the model you actually use in app.py
model = joblib.load("models/random_forest.pkl")  # or lightgbm.pkl or final_model.pkl

print("✅ Model loaded successfully!")
print("📊 Features expected by the model:\n")
print(model.feature_names_in_)
print(f"\nTotal features: {len(model.feature_names_in_)}")
