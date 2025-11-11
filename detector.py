# detector.py
import subprocess
import time
import pandas as pd
import joblib
import socketio
import os
import sys
from datetime import datetime

# --- CONFIGURATION ---
# 1. FIX THE MODEL PATH
MODEL_PATH = 'models/reduced_model.pkl'

# 2. VERIFY YOUR TSHARK PATH
# Find tshark.exe on your system and paste the full path here.
TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe"

# 3. SET YOUR NETWORK INTERFACE
# Run 'tshark -D' in your terminal to see a list.
# Example: 'Wi-Fi', 'Ethernet', etc.
NETWORK_INTERFACE = "Wi-Fi"

CAPTURE_DURATION = "10"  # Capture duration in seconds for each batch
PCAP_FILE = "live_capture.pcapng"
CSV_FILE = "live_capture.csv"
# --- END CONFIGURATION ---

# Create a Socket.IO client instance
sio = socketio.Client()

print("Attempting to load model...")
try:
    model = joblib.load(MODEL_PATH)
    print(f"✅ Model '{MODEL_PATH}' loaded successfully.")
except FileNotFoundError:
    print(f"❌ CRITICAL ERROR: Model file not found at '{MODEL_PATH}'")
    print("Please train your model using main.py or fix the MODEL_PATH variable.")
    sys.exit(1)
except Exception as e:
    print(f"❌ CRITICAL ERROR: Failed to load model. Error: {e}")
    sys.exit(1)


@sio.event
def connect():
    print("✅ Connected to dashboard server.")


@sio.event
def connect_error(data):
    print("❌ Connection to dashboard server failed!")


@sio.event
def disconnect():
    print("Disconnected from dashboard server.")


def capture_packets():
    """Captures packets using tshark."""
    print(f"Capturing packets on interface '{NETWORK_INTERFACE}' for {CAPTURE_DURATION} seconds...")
    capture_command = [
        TSHARK_PATH,
        "-i", NETWORK_INTERFACE,
        "-a", f"duration:{CAPTURE_DURATION}",
        "-w", PCAP_FILE
    ]
    try:
        subprocess.run(capture_command, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Packets captured and saved to '{PCAP_FILE}'.")
        return True
    except FileNotFoundError:
        print(f"❌ CRITICAL ERROR: 'tshark.exe' not found at '{TSHARK_PATH}'")
        print("Please install Wireshark and verify the TSHARK_PATH variable in detector.py.")
        return False
    except subprocess.CalledProcessError as e:
        print(f"❌ CRITICAL ERROR: tshark failed. Return code: {e.returncode}")
        print("This often means you need to run this terminal as Administrator.")
        print(f"Or, does the interface '{NETWORK_INTERFACE}' exist? Run 'tshark -D' to check.")
        return False


def convert_pcap_to_csv():
    """Converts pcap to csv using tshark."""
    print(f"Converting '{PCAP_FILE}' to '{CSV_FILE}'...")
    # This command defines the exact columns to match your training data
    fields = "-e frame.time_epoch -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e ip.proto -e ip.len -e tcp.flags -e tcp.len -e udp.length"
    convert_command = [
                          TSHARK_PATH,
                          "-r", PCAP_FILE,
                          "-T", "fields",
                      ] + fields.split() + [
                          "-E", "header=y",
                          "-E", "separator=,",
                      ]

    try:
        with open(CSV_FILE, 'w') as f:
            subprocess.run(convert_command, check=True, stdout=f, stderr=subprocess.DEVNULL)
        print(f"Successfully converted to '{CSV_FILE}'.")
        return True
    except Exception as e:
        print(f"❌ ERROR: Failed to convert pcap to csv. {e}")
        return False


def preprocess_and_predict():
    """Loads CSV, preprocesses it, and yields predictions."""
    print("Loading captured data for prediction...")
    try:
        df = pd.read_csv(CSV_FILE)
    except Exception as e:
        print(f"❌ ERROR: Could not read CSV '{CSV_FILE}'. Is it empty? {e}")
        return

    # --- Feature Extraction (Must match your training script) ---

    # Fill NaN values (e.g., tcp ports for udp packets and vice-versa)
    df = df.fillna(0)

    # Example: Create a 'port' feature
    df['src_port'] = df['tcp.srcport'].combine_first(df['udp.srcport'])
    df['dst_port'] = df['tcp.dstport'].combine_first(df['udp.dstport'])

    # Select features for the model
    # THIS LIST NOW MATCHES YOUR TRAINING SCRIPT (6 features)
    features_to_use = [
        'ip.len',
        'ip.proto',  # <-- THE MISSING FEATURE
        'tcp.len',
        'udp.length',
        'src_port',
        'dst_port'
    ]

    # Ensure all required columns exist, fill with 0 if not
    for col in features_to_use:
        if col not in df.columns:
            print(f"⚠️ Warning: Feature '{col}' not in captured data. Adding as 0.")
            df[col] = 0

    X_live = df[features_to_use]
    # --- End Feature Extraction ---

    print(f"Making predictions on {len(X_live)} packets...")
    if not X_live.empty:
        try:
            # Use .values to pass a NumPy array and avoid the feature name warning
            predictions = model.predict(X_live.values)

            # Send each prediction
            for i, (index, row) in enumerate(df.iterrows()):
                pred = predictions[i]
                payload = {
                    "timestamp": datetime.fromtimestamp(int(row['frame.time_epoch'])).strftime('%Y-%m-%d %H:%M:%S'),
                    "prediction": str(pred),
                    "meta": {
                        "src": row.get('ip.src', 'N/A'),
                        "dst": row.get('ip.dst', 'N/A'),
                        "proto": row.get('ip.proto', 'N/A')
                    }
                }

                # Send the prediction to the dashboard
                sio.emit('new_prediction', payload)

            print(f"✅ Sent {len(predictions)} predictions to dashboard.")

        except Exception as e:
            print(f"❌ CRITICAL ERROR: Prediction failed. {e}")
            print("This usually means your live features do not match your training features.")
            print("Live features:", X_live.columns.to_list())


def cleanup():
    """Removes temporary files."""
    if os.path.exists(PCAP_FILE):
        os.remove(PCAP_FILE)
    if os.path.exists(CSV_FILE):
        os.remove(CSV_FILE)
    print("Cleanup complete.")


def main_loop():
    while True:
        try:
            if capture_packets():
                if convert_pcap_to_csv():
                    preprocess_and_predict()

            cleanup()
            print(f"--- Cycle complete. Waiting {CAPTURE_DURATION} seconds. ---")
            time.sleep(int(CAPTURE_DURATION))

        except KeyboardInterrupt:
            print("\nStopping detector...")
            cleanup()
            break
        except Exception as e:
            print(f"An unexpected error occurred in main loop: {e}")
            cleanup()
            time.sleep(10)


if __name__ == '__main__':
    try:
        sio.connect('http://localhost:5000')
        main_loop()
    except socketio.exceptions.ConnectionError:
        print("❌ CRITICAL ERROR: Cannot connect to dashboard server at http://localhost:5000.")
        print("Is app.py running?")
    finally:
        if sio.connected:
            sio.disconnect()