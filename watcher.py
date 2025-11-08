# watcher.py
import os
import time
import json
import joblib
import pandas as pd
import socketio
import traceback
from pathlib import Path
from datetime import datetime
import subprocess

# CONFIG
MODEL_PATHS = [
    "models/reduced_model.pkl",
    "models/random_forest.pkl",
    "models/final_model.pkl",
    "model.pkl"
]
SCALER_PATHS = [
    "models/reduced_scaler.pkl",
    "models/scaler.pkl",
    "scaler.pkl"
]
FEATURE_FILE = "data/live_cleaned.csv"   # feature extractor should write here (or adjust)
PCAP_FILE = "data/capture.pcapng"        # watched capture file
EXTRACT_SCRIPT = "extract_features_from_pycap.py"  # script that produces FEATURE_FILE
CHECK_INTERVAL = 3                        # seconds

# The feature order your model expects
EXPECTED_FEATURES = ['src_port', 'dst_port', 'packet_length', 'protocol', 'inter_arrival_time', 'tcp_flags']

# Protocol name -> number mapping (common)
PROTO_MAP = {
    'TCP': 6, 'UDP': 17, 'ICMP': 1, 'TLS': 6, 'HTTP': 6, 'DNS': 17, 'ARP': 0
}

# SocketIO client
sio = socketio.Client(reconnection=True, reconnection_attempts=5, logger=False, engineio_logger=False)

def find_first(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None

def safe_load_model():
    model_path = find_first(MODEL_PATHS)
    scaler_path = find_first(SCALER_PATHS)
    if not model_path:
        raise FileNotFoundError("No model file found. Checked: " + ", ".join(MODEL_PATHS))
    if not scaler_path:
        raise FileNotFoundError("No scaler file found. Checked: " + ", ".join(SCALER_PATHS))

    print("✅ Loading model:", model_path)
    model = joblib.load(model_path)
    print("✅ Loading scaler:", scaler_path)
    scaler = joblib.load(scaler_path)
    return model, scaler

def ensure_features_df(df):
    """
    Return DataFrame with exactly EXPECTED_FEATURES columns in order.
    Try to map/convert types if necessary.
    """
    df = df.copy()

    # Normalize column names (strip spaces)
    df.columns = [c.strip() for c in df.columns]

    # Map protocol strings to numbers if needed
    if 'protocol' in df.columns:
        # If values look like strings (e.g., TLS), map them
        if df['protocol'].dtype == object:
            df['protocol'] = df['protocol'].apply(lambda x: PROTO_MAP.get(str(x).upper(), pd.to_numeric(x, errors='coerce')))
        else:
            # numeric dtype; keep
            df['protocol'] = pd.to_numeric(df['protocol'], errors='coerce')

    # Convert numeric columns
    for col in ['src_port', 'dst_port', 'packet_length', 'inter_arrival_time', 'tcp_flags']:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce')

    # Fill missing expected columns with zeros
    for col in EXPECTED_FEATURES:
        if col not in df.columns:
            df[col] = 0

    # Reorder
    df = df[EXPECTED_FEATURES]

    # Drop rows with all-NaN or where essential numeric fields are NaN
    df = df.dropna(subset=['src_port', 'dst_port', 'packet_length'], how='all')
    df = df.fillna(0)
    return df

def extract_features_from_pcap():
    """
    If you have a script that extracts features (extract_features_from_pycap.py),
    run it here. The script must write FEATURE_FILE.
    """
    if not os.path.exists(EXTRACT_SCRIPT):
        # no extractor script: nothing to do
        return False, "No extractor script found"
    try:
        # run extractor (assumes it writes FEATURE_FILE)
        subprocess.run(["python", EXTRACT_SCRIPT], check=True)
        return True, None
    except Exception as e:
        return False, str(e)

def emit_predictions(preds, meta=None):
    payload = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "prediction": preds if isinstance(preds, list) else [preds],
        "meta": meta or {"src": "watcher"}
    }
    try:
        sio.emit("new_prediction", json.dumps(payload))
        print("[watcher] 🔥 Emitted:", payload)
    except Exception as e:
        print("[watcher] ❌ Failed to emit:", e)

def main():
    # connect to server
    try:
        sio.connect("http://localhost:5000", wait=True, namespaces=["/"])
        print("✅ Connected to dashboard socket server")
    except Exception as e:
        print("⚠️ Could not connect to dashboard socket server:", e)
        # continue — we'll still write logs locally and try to emit later

    model, scaler = safe_load_model()

    # Track file-mod time; if extractor script exists we'll watch PCAP; otherwise watch FEATURE_FILE
    watch_path = PCAP_FILE if os.path.exists(PCAP_FILE) and os.path.exists(EXTRACT_SCRIPT) else FEATURE_FILE
    last_mtime = 0

    print(f"[watcher] Watching: {watch_path}")

    while True:
        try:
            if watch_path == PCAP_FILE:
                # PCAP-based flow: run extractor when PCAP is updated
                if os.path.exists(PCAP_FILE):
                    mtime = os.path.getmtime(PCAP_FILE)
                    if mtime != last_mtime:
                        print("[watcher] Detected PCAP change — extracting features...")
                        ok, err = extract_features_from_pcap()
                        if not ok:
                            print("[watcher] Extractor failed:", err)
                        last_mtime = mtime
            # Now check if feature file exists and changed
            if os.path.exists(FEATURE_FILE):
                mtime = os.path.getmtime(FEATURE_FILE)
                if mtime != last_mtime:
                    print("[watcher] Extracting latest features from:", FEATURE_FILE)
                    df = pd.read_csv(FEATURE_FILE)
                    df_proc = ensure_features_df(df)
                    if df_proc.shape[0] == 0:
                        print("[watcher] No usable rows in feature file")
                    else:
                        # Scale and predict in batches
                        try:
                            X_scaled = scaler.transform(df_proc)  # scaler may expect same column order
                        except Exception as e:
                            print("[watcher] Scaling failed:", e)
                            # try fallback: use numpy array (drop names)
                            try:
                                import numpy as np
                                X_scaled = scaler.transform(np.array(df_proc, dtype=float))
                            except Exception as e2:
                                print("[watcher] Fallback scaling failed:", e2)
                                raise

                        y_pred = model.predict(X_scaled)
                        # convert numpy -> python list of labels
                        preds = [str(p) for p in list(y_pred)]
                        emit_predictions(preds, meta={"src": "watcher"})
                    last_mtime = mtime
        except Exception as e:
            print("[watcher] ERROR:", e)
            traceback.print_exc()

        time.sleep(CHECK_INTERVAL)

if __name__ == "__main__":
    main()
