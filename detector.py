# detector.py (Stable Continuous Version)

import os
import pickle
import subprocess
import socketio
import pyshark
import numpy as np
import pandas as pd
import time
from collections import defaultdict

PCAP_FILE = "live.pcap"

# -----------------------------
# Load Model
# -----------------------------
print("Loading model...")

with open("models/model.pkl", "rb") as f:
    model = pickle.load(f)

with open("models/scaler.pkl", "rb") as f:
    scaler = pickle.load(f)

with open("models/features.pkl", "rb") as f:
    feature_order = pickle.load(f)

# -----------------------------
# Connect to Dashboard
# -----------------------------
sio = socketio.Client()
sio.connect("http://localhost:5050")

print("Starting Continuous IDS Monitoring...")

# =============================
# CONTINUOUS LOOP
# =============================
while True:

    try:
        print("\nCapturing 10 seconds of traffic...")

        process = subprocess.Popen([
            r"C:\Program Files\Wireshark\tshark.exe",
            "-i", "Wi-Fi",
            "-a", "duration:10",
            "-w", PCAP_FILE
        ])

        process.wait(timeout=20)

        flows = {}

        capture = pyshark.FileCapture(PCAP_FILE)

        for packet in capture:
            try:
                if not hasattr(packet, "ip"):
                    continue

                src = packet.ip.src
                dst = packet.ip.dst
                proto = packet.transport_layer
                length = int(packet.length)
                timestamp = float(packet.sniff_timestamp)

                if proto not in ["TCP", "UDP"]:
                    continue

                src_port = packet[proto].srcport
                dst_port = packet[proto].dstport

                key = (src, dst, src_port, dst_port, proto)
                reverse = (dst, src, dst_port, src_port, proto)

                if reverse in flows:
                    flow = flows[reverse]
                    direction = "bwd"
                else:
                    flow = flows.setdefault(key, {
                        "start": timestamp,
                        "end": timestamp,
                        "fwd_packets": 0,
                        "bwd_packets": 0,
                        "fwd_bytes": 0,
                        "bwd_bytes": 0,
                        "lengths": [],
                        "times": []
                    })
                    direction = "fwd"

                flow["end"] = timestamp
                flow["lengths"].append(length)
                flow["times"].append(timestamp)

                if direction == "fwd":
                    flow["fwd_packets"] += 1
                    flow["fwd_bytes"] += length
                else:
                    flow["bwd_packets"] += 1
                    flow["bwd_bytes"] += length

            except:
                continue

        capture.close()

        feature_rows = []

        for flow in flows.values():
            duration = flow["end"] - flow["start"]
            if duration <= 0:
                duration = 1e-6

            total_packets = flow["fwd_packets"] + flow["bwd_packets"]
            total_bytes = flow["fwd_bytes"] + flow["bwd_bytes"]

            lengths = np.array(flow["lengths"])
            iats = np.diff(flow["times"])

            feature_rows.append({
                "Flow Duration": duration,
                "Total Fwd Packets": flow["fwd_packets"],
                "Total Backward Packets": flow["bwd_packets"],
                "Total Length of Fwd Packets": flow["fwd_bytes"],
                "Total Length of Bwd Packets": flow["bwd_bytes"],
                "Flow Bytes/s": total_bytes / duration,
                "Flow Packets/s": total_packets / duration,
                "Packet Length Mean": lengths.mean(),
                "Packet Length Std": lengths.std(),
                "Fwd IAT Mean": iats.mean() if len(iats) > 0 else 0,
                "Fwd IAT Std": iats.std() if len(iats) > 0 else 0,
                "Bwd IAT Mean": iats.mean() if len(iats) > 0 else 0,
                "Bwd IAT Std": iats.std() if len(iats) > 0 else 0
            })

        if not feature_rows:
            print("No flows detected.")
            continue

        df = pd.DataFrame(feature_rows)
        df = df[feature_order]

        X_scaled = scaler.transform(df)

        probs = model.predict_proba(X_scaled)[:, 1]
        preds = (probs > 0.8).astype(int)

        attack_count = sum(preds)

        print(f"Flows: {len(preds)} | Attacks: {attack_count}")

        for p, prob in zip(preds, probs):
            sio.emit("prediction", {
                "prediction": int(p),
                "probability": float(prob)
            })

        # Cleanup PCAP to prevent disk growth
        if os.path.exists(PCAP_FILE):
            os.remove(PCAP_FILE)

        time.sleep(2)

    except Exception as e:
        print("Loop error:", e)
        time.sleep(3)
        continue