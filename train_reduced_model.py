import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from imblearn.over_sampling import SMOTE
import os

# 1️⃣ Load dataset
df = pd.read_csv("data/train.csv")
print("📦 Loaded training data:", df.shape)
print(df.head(), "\n")

# 2️⃣ Label distribution check
print("📊 Original Label Distribution:")
print(df["label"].value_counts(), "\n")

# 3️⃣ Select only the features that detector.py will extract
# CRITICAL: These must match exactly what detector.py extracts in preprocess_and_predict()
REQUIRED_FEATURES = [
    'ip.len',
    'ip.proto',
    'tcp.len',
    'udp.length',
    'src_port',
    'dst_port'
]

# Check if all required features exist
missing_features = [f for f in REQUIRED_FEATURES if f not in df.columns]
if missing_features:
    print(f"⚠️ WARNING: Missing features in training data: {missing_features}")
    print("Available columns:", df.columns.tolist())
    print("\n❌ ERROR: Training data must contain all required features!")
    print("Required features:", REQUIRED_FEATURES)
    raise ValueError(f"Missing required features: {missing_features}")

# Use only the required features (matching detector.py)
X = df[REQUIRED_FEATURES]
y = df["label"]
print(f"✅ Using {len(REQUIRED_FEATURES)} features matching detector.py: {REQUIRED_FEATURES}")

# 4️⃣ Scale numeric features
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# 5️⃣ Apply SMOTE for class balance
print("⚙️ Applying SMOTE to balance classes...")
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X_scaled, y)
print("✅ After SMOTE:", X_resampled.shape)
print(pd.Series(y_resampled).value_counts(), "\n")

# 6️⃣ Split the resampled data
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
)

# 7️⃣ Train Random Forest with class weighting
clf = RandomForestClassifier(
    n_estimators=300,
    max_depth=15,
    random_state=42,
    n_jobs=-1,
    class_weight="balanced"
)
clf.fit(X_train, y_train)

# 8️⃣ Evaluate the model
acc = clf.score(X_test, y_test)
print(f"✅ Model trained successfully! Accuracy: {acc:.3f}\n")

y_pred = clf.predict(X_test)
print("📋 Classification Report:")
print(classification_report(y_test, y_pred))

print("🔍 Confusion Matrix:")
print(confusion_matrix(y_test, y_pred))

# 9️⃣ Save model and scaler
os.makedirs("models", exist_ok=True)
joblib.dump(clf, "models/reduced_model.pkl")
joblib.dump(scaler, "models/reduced_scaler.pkl")

print("\n💾 Model saved to: models/reduced_model.pkl")
print("💾 Scaler saved to: models/reduced_scaler.pkl")
print("🔥 Training complete — this model actually detects attacks now.")
