import os
import pandas as pd
import joblib
import numpy as np
from datetime import datetime

# ==============================
#  CONFIG
# ==============================
MODEL_PATH = "models/reduced_model.pkl"
SCALER_PATH = "models/reduced_scaler.pkl"
LIVE_DATA_PATH = "data/live.csv"
OUTPUT_DIR = "predictions"
LOG_FILE = "logs/predict_log.txt"
EXPECTED_FEATURES = [
    "src_port", "dst_port", "packet_length",
    "protocol", "inter_arrival_time", "tcp_flags"
]

# ==============================
#  SAFE LOGGER (UTF-8 compatible)
# ==============================
def log_message(msg):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, "a", encoding="utf-8") as f:  # ✅ force UTF-8 encoding
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{timestamp}] {msg}\n")
    print(msg)


# ==============================
#  MAIN
# ==============================
try:
    log_message("🚀 Starting live prediction process...")

    # 1️⃣ Load model + scaler
    if not os.path.exists(MODEL_PATH) or not os.path.exists(SCALER_PATH):
        raise FileNotFoundError("❌ Model or Scaler file missing in /models directory.")

    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    log_message("✅ Model & Scaler loaded successfully.")

    # 2️⃣ Load live data
    if not os.path.exists(LIVE_DATA_PATH):
        raise FileNotFoundError(f"❌ Live data file not found: {LIVE_DATA_PATH}")

    live_data = pd.read_csv(LIVE_DATA_PATH)
    log_message(f"📡 Live data loaded: {live_data.shape}")

    # 3️⃣ Validate columns
    missing_cols = [col for col in EXPECTED_FEATURES if col not in live_data.columns]
    if missing_cols:
        raise ValueError(f"❌ Missing columns in live data: {missing_cols}")

    df = live_data[EXPECTED_FEATURES].copy()

    # 4️⃣ Check for empty data
    if df.empty:
        raise ValueError("❌ Live CSV is empty or filtered data is empty.")

    # 5️⃣ Scale
    X_scaled = scaler.transform(df)

    # 6️⃣ Predict
    preds = model.predict(X_scaled)

    # 7️⃣ Save output
    live_data["prediction"] = preds
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_path = os.path.join(OUTPUT_DIR, f"live_predictions_{timestamp}.csv")
    live_data.to_csv(output_path, index=False)

    log_message(f"✅ Predictions generated successfully! Saved to: {output_path}")
    log_message(f"📊 Preview:\n{live_data.head()}")

except Exception as e:
    log_message(f"💥 ERROR: {str(e)}")

log_message("🏁 Prediction run complete.\n")
