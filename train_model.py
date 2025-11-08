import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from lightgbm import LGBMClassifier
from imblearn.over_sampling import SMOTE
import joblib
import time
import numpy as np

print("🚀 Loading processed data...")

# ======================
# Load the processed data
# ======================
X_train = pd.read_csv("data/X_train.csv")
X_test = pd.read_csv("data/X_test.csv")
y_train = pd.read_csv("data/y_train.csv").squeeze()
y_test = pd.read_csv("data/y_test.csv").squeeze()

print(f"✅ Data loaded successfully. Train: {X_train.shape}, Test: {X_test.shape}")

# ======================
# Align features to avoid mismatches
# ======================
common_cols = X_train.columns.intersection(X_test.columns)
X_train = X_train[common_cols]
X_test = X_test[common_cols]

# ======================
# Scale features
# ======================
print("📏 Scaling features...")
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# ======================
# Apply SMOTE for class balancing (sampled to 100k max for efficiency)
# ======================
print("⚖️ Applying SMOTE balancing...")
if len(X_train_scaled) > 100000:
    X_train_sub, _, y_train_sub, _ = train_test_split(
        X_train_scaled, y_train, stratify=y_train, train_size=100000, random_state=42
    )
else:
    X_train_sub, y_train_sub = X_train_scaled, y_train

smote = SMOTE(random_state=42)
X_train_bal, y_train_bal = smote.fit_resample(X_train_sub, y_train_sub)

# ✅ Reattach column names (critical for API compatibility)
X_train_bal = pd.DataFrame(X_train_bal, columns=common_cols)
print(f"After SMOTE: {X_train_bal.shape}")

# ======================
# Define models
# ======================
models = {
    "random_forest": RandomForestClassifier(
        n_estimators=200, max_depth=25, n_jobs=-1, random_state=42
    ),
    "lightgbm": LGBMClassifier(
        n_estimators=300, learning_rate=0.05, num_leaves=40, random_state=42, n_jobs=-1
    )
}

results = {}

# ======================
# Train & evaluate
# ======================
for name, model in models.items():
    print(f"\n🔹 Training {name}...")
    start = time.time()
    model.fit(X_train_bal, y_train_bal)
    duration = time.time() - start

    y_pred = model.predict(X_test_scaled)
    acc = accuracy_score(y_test, y_pred)

    print(f"✅ {name} trained in {duration:.2f}s | Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    cm = confusion_matrix(y_test, y_pred)
    results[name] = {"accuracy": acc, "time": duration, "confusion_matrix": cm}

    os.makedirs("models", exist_ok=True)

    # ✅ Save model, feature names, and scaler
    save_path = f"models/{name}.pkl"
    joblib.dump(model, save_path)
    joblib.dump(scaler, "models/scaler.pkl")

    # Save feature names separately (since LightGBM blocks setting the attribute)
    joblib.dump(common_cols.to_list(), "models/feature_names.pkl")

    print(f"💾 Saved {name}, scaler, and feature names to models/")

# ======================
# Feature importance (LightGBM)
# ======================
if "lightgbm" in models:
    model = models["lightgbm"]
    if hasattr(model, "feature_importances_"):
        imp = pd.Series(model.feature_importances_, index=common_cols).sort_values(ascending=False)
        imp.to_csv("models/feature_importance.csv")
        print("📊 Feature importances saved to models/feature_importance.csv")

print("\n🎯 All training complete. Models saved in 'models/' folder.")
