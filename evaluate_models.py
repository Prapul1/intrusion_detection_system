import os
import pandas as pd
import joblib
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

# ================================================================
# 🧩 Attack Category Mapping (KDD99 taxonomy)
# ================================================================
attack_category_mapping = {
    0: "Normal",
    1: "DoS", 2: "DoS", 3: "DoS", 4: "DoS", 5: "DoS", 6: "DoS", 7: "DoS", 8: "DoS", 9: "DoS",
    10: "Probe", 11: "Probe", 12: "Probe", 13: "Probe",
    14: "R2L", 15: "R2L", 16: "R2L", 17: "R2L",
    18: "U2R", 19: "U2R", 20: "U2R", 21: "U2R"
}

# ================================================================
# 🚀 STEP 1: Load processed test data
# ================================================================
print("🚀 Loading test data...")
X_test = pd.read_csv("data/X_test.csv")
y_test = pd.read_csv("data/y_test.csv").values.ravel()
print(f"✅ Test data loaded. Shape: {X_test.shape}")

# ================================================================
# 🧠 STEP 2: Load trained models
# ================================================================
model_dir = "models"
model_files = [f for f in os.listdir(model_dir) if f.endswith(".pkl")]

if not model_files:
    raise FileNotFoundError("❌ No trained models found in 'models/' folder. Train them first!")

print(f"🧠 Found {len(model_files)} models:")
for mf in model_files:
    print(f"   - {mf}")

# Ensure results folder exists
os.makedirs("results", exist_ok=True)

# ================================================================
# 🎯 STEP 3: Evaluate each model
# ================================================================
results = []

for mf in model_files:
    model_path = os.path.join(model_dir, mf)
    model_name = mf.replace(".pkl", "")

    print(f"\n🔹 Evaluating {model_name}...")
    model = joblib.load(model_path)

    # Make predictions
    y_pred = model.predict(X_test)

    # Convert numeric predictions to categories for readability
    y_test_category = [attack_category_mapping.get(i, "Unknown") for i in y_test]
    y_pred_category = [attack_category_mapping.get(i, "Unknown") for i in y_pred]

    # Accuracy and metrics
    acc = accuracy_score(y_test, y_pred)
    print(f"✅ {model_name} Accuracy: {acc:.4f}")
    print(classification_report(y_test, y_pred, zero_division=0))

    # ================================================================
    # 📊 Confusion Matrix
    # ================================================================
    cm = confusion_matrix(y_test, y_pred)

    plt.figure(figsize=(12, 10))
    sns.heatmap(cm, cmap="coolwarm", cbar=False)
    plt.title(f"Confusion Matrix - {model_name}", fontsize=14)
    plt.xlabel("Predicted Label", fontsize=12)
    plt.ylabel("True Label", fontsize=12)
    plt.tight_layout()

    cm_path = f"results/confusion_matrix_{model_name}.png"
    plt.savefig(cm_path)
    plt.close()

    print(f"📉 Confusion matrix saved: {cm_path}")

    results.append((model_name, acc))

# ================================================================
# 🏁 STEP 4: Model Performance Summary
# ================================================================
print("\n📊 Model Performance Summary:")
for name, acc in sorted(results, key=lambda x: x[1], reverse=True):
    print(f"   {name}: {acc:.4f}")

best_model = max(results, key=lambda x: x[1])
print(f"\n🏆 Best Model: {best_model[0]} with accuracy {best_model[1]:.4f}")
