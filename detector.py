# detector.py — Risk IDS with MITRE ATT&CK Mapping

import os
import joblib
import subprocess
import socketio
import pyshark
import numpy as np
import pandas as pd
import time
import argparse
import platform

from mitre_mapper import map_to_mitre

parser = argparse.ArgumentParser(description="Risk-Based ML IDS")
parser.add_argument("--interface", default="Wi-Fi")
parser.add_argument("--duration", type=int, default=10)
parser.add_argument("--threshold", type=float, default=0.8)
parser.add_argument("--dashboard", default="http://localhost:5050")
args = parser.parse_args()

INTERFACE     = args.interface
DURATION      = args.duration
THRESHOLD     = args.threshold
DASHBOARD_URL = args.dashboard
PCAP_FILE     = "live.pcap"

FEATURE_ORDER = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Packet Length Std",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Bwd IAT Mean",
    "Bwd IAT Std"
]

# ── Resolve friendly interface name to full device path on Windows ────────────
def resolve_interface(name: str) -> str:
    """
    On Windows, tshark needs the full \\Device\\NPF_{GUID} path.
    If the user passes a friendly name like 'Wi-Fi', resolve it.
    On Linux, interface names like 'eth0' work directly.
    """
    if platform.system() != "Windows":
        return name

    # Already a full device path
    if name.startswith("\\Device\\") or name.startswith(r"\Device"):
        return name

    tshark = r"C:\Program Files\Wireshark\tshark.exe"
    try:
        result = subprocess.run([tshark, "-D"],
                                capture_output=True, text=True, timeout=10)
        for line in result.stdout.strip().split("\n"):
            # Line format: "5. \Device\NPF_{GUID} (Wi-Fi)"
            if f"({name})" in line:
                parts = line.split(".", 1)
                if len(parts) == 2:
                    device_path = parts[1].strip().split(" ")[0].strip()
                    print(f"✅ Resolved '{name}' → {device_path}")
                    return device_path
        print(f"⚠️  Could not resolve '{name}', using as-is.")
    except Exception as e:
        print(f"⚠️  Interface resolution error: {e}")
    return name

# ── Load model ────────────────────────────────────────────────────────────────
print("Loading model...")
try:
    model  = joblib.load("models/model.pkl")
    scaler = joblib.load("models/scaler.pkl")
    print("✅ Model and scaler loaded.")
except FileNotFoundError as e:
    print(f"❌ ERROR: {e}")
    exit(1)

# ── Resolve interface ─────────────────────────────────────────────────────────
INTERFACE = resolve_interface(INTERFACE)

# ── Connect to dashboard with retry ──────────────────────────────────────────
sio = socketio.Client()
connected = False
print(f"Connecting to dashboard at {DASHBOARD_URL}...")
for attempt in range(10):
    try:
        sio.connect(DASHBOARD_URL)
        connected = True
        print("✅ Connected to dashboard.")
        break
    except Exception as e:
        print(f"  Attempt {attempt+1}/10 failed: {e}. Retrying in 3s...")
        time.sleep(3)

if not connected:
    print("❌ Could not connect to dashboard. Is app.py running?")
    exit(1)

TSHARK_PATH = r"C:\Program Files\Wireshark\tshark.exe" if platform.system() == "Windows" else "tshark"

print(f"\n🚀 IDS running on: {INTERFACE}")
print(f"   Window: {DURATION}s | Threshold: {THRESHOLD}\n")

while True:
    try:
        print("\n📡 Capturing traffic...")

        process = subprocess.Popen([
            TSHARK_PATH, "-i", INTERFACE,
            "-a", f"duration:{DURATION}",
            "-w", PCAP_FILE
        ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        process.wait(timeout=DURATION + 10)

        if not os.path.exists(PCAP_FILE) or os.path.getsize(PCAP_FILE) == 0:
            print("⚠️  No capture file or empty. Check interface.")
            time.sleep(3)
            continue

        # ── Parse packets into flows ──────────────────────────────────────
        flows = {}
        capture = pyshark.FileCapture(PCAP_FILE)

        for packet in capture:
            try:
                if not hasattr(packet, "ip"):
                    continue
                proto = packet.transport_layer
                if proto not in ["TCP", "UDP"]:
                    continue

                length    = int(packet.length)
                timestamp = float(packet.sniff_timestamp)
                src       = packet.ip.src
                dst       = packet.ip.dst
                src_port  = int(packet[proto].srcport)
                dst_port  = int(packet[proto].dstport)

                key     = (src, dst, src_port, dst_port, proto)
                reverse = (dst, src, dst_port, src_port, proto)

                if reverse in flows:
                    flow      = flows[reverse]
                    direction = "bwd"
                else:
                    flow = flows.setdefault(key, {
                        "start": timestamp, "end": timestamp,
                        "fwd_packets": 0, "bwd_packets": 0,
                        "fwd_bytes": 0,   "bwd_bytes": 0,
                        "lengths": [],    "times": [],
                        "src_port": src_port, "dst_port": dst_port
                    })
                    direction = "fwd"

                flow["end"] = timestamp
                flow["lengths"].append(length)
                flow["times"].append(timestamp)

                if direction == "fwd":
                    flow["fwd_packets"] += 1
                    flow["fwd_bytes"]   += length
                else:
                    flow["bwd_packets"] += 1
                    flow["bwd_bytes"]   += length

            except Exception:
                continue

        capture.close()

        if not flows:
            print("⚠️  No flows detected.")
            if os.path.exists(PCAP_FILE):
                os.remove(PCAP_FILE)
            time.sleep(2)
            continue

        # ── Build feature rows ────────────────────────────────────────────
        feature_rows = []
        flow_list    = []

        for flow in flows.values():
            duration = max(flow["end"] - flow["start"], 1e-6)

            total_packets = flow["fwd_packets"] + flow["bwd_packets"]
            total_bytes   = flow["fwd_bytes"]   + flow["bwd_bytes"]

            lengths = np.array(flow["lengths"])
            times   = np.array(flow["times"])

            fwd_times = times[:flow["fwd_packets"]] if flow["fwd_packets"] > 1 else np.array([0.0])
            bwd_times = times[flow["fwd_packets"]:] if flow["bwd_packets"] > 1 else np.array([0.0])
            fwd_iats  = np.diff(fwd_times) if len(fwd_times) > 1 else np.array([0.0])
            bwd_iats  = np.diff(bwd_times) if len(bwd_times) > 1 else np.array([0.0])

            row = {
                "Flow Duration":               duration,
                "Total Fwd Packets":           flow["fwd_packets"],
                "Total Backward Packets":      flow["bwd_packets"],
                "Total Length of Fwd Packets": flow["fwd_bytes"],
                "Total Length of Bwd Packets": flow["bwd_bytes"],
                "Flow Bytes/s":                total_bytes / duration,
                "Flow Packets/s":              total_packets / duration,
                "Packet Length Mean":          float(lengths.mean()),
                "Packet Length Std":           float(lengths.std()),
                "Fwd IAT Mean":                float(fwd_iats.mean()),
                "Fwd IAT Std":                 float(fwd_iats.std()),
                "Bwd IAT Mean":                float(bwd_iats.mean()),
                "Bwd IAT Std":                 float(bwd_iats.std()),
                "src_port": flow["src_port"],
                "dst_port": flow["dst_port"],
            }
            feature_rows.append(row)
            flow_list.append(row)

        df = pd.DataFrame(feature_rows)
        df.replace([np.inf, -np.inf], 0, inplace=True)
        df.fillna(0, inplace=True)

        X_scaled = scaler.transform(df[FEATURE_ORDER])
        probs     = model.predict_proba(X_scaled)[:, 1]

        window_flows    = len(probs)
        avg_prob        = float(np.mean(probs))
        max_prob        = float(np.max(probs))
        high_risk_count = int(sum(p > THRESHOLD for p in probs))

        print(f"✅ Flows: {window_flows} | High Risk: {high_risk_count} | Avg: {avg_prob:.4f} | Max: {max_prob:.4f}")

        for prob, flow_row in zip(probs, flow_list):
            if prob > 0.8:
                level = "high"
            elif prob > 0.3:
                level = "medium"
            else:
                continue

            technique = map_to_mitre(flow_row, prob)

            payload = {
                "risk_level":     level,
                "probability":    float(prob),
                "technique_id":   technique.technique_id if technique else "",
                "technique_name": technique.name         if technique else "",
                "tactic":         technique.tactic       if technique else "",
            }

            if technique:
                print(f"  🎯 {level.upper()} | prob={prob:.3f} | {technique.technique_id} · {technique.name}")

            sio.emit("prediction", payload)

        sio.emit("window_update", {
            "window_flows":    window_flows,
            "avg_probability": avg_prob,
            "max_probability": max_prob,
            "high_risk_count": high_risk_count
        })

        if os.path.exists(PCAP_FILE):
            os.remove(PCAP_FILE)

        time.sleep(2)

    except KeyboardInterrupt:
        print("\n🛑 Stopped.")
        sio.disconnect()
        break
    except Exception as e:
        print(f"⚠️  Loop error: {e}")
        time.sleep(3)