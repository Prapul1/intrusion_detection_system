import pyshark
import pandas as pd
import numpy as np
from tqdm import tqdm

# ====== CONFIG ======
pcap_file = "capture.pcapng"  # File name (ensure it's in your project root)
output_csv = "data/live_features.csv"
# ====================

print("🚀 Reading packets from:", pcap_file)

try:
    capture = pyshark.FileCapture(pcap_file)
except Exception as e:
    print("❌ Error reading pcap:", e)
    exit()

features = []
last_time = None

for packet in tqdm(capture, desc="📡 Extracting features"):
    try:
        timestamp = float(packet.sniff_timestamp)
        if last_time:
            inter_time = timestamp - last_time
        else:
            inter_time = 0.0
        last_time = timestamp

        proto = packet.highest_layer
        length = int(packet.length)

        src_ip = getattr(packet.ip, "src", "0.0.0.0") if hasattr(packet, "ip") else "0.0.0.0"
        dst_ip = getattr(packet.ip, "dst", "0.0.0.0") if hasattr(packet, "ip") else "0.0.0.0"

        src_port = getattr(packet[packet.transport_layer], "srcport", 0) if hasattr(packet, "transport_layer") else 0
        dst_port = getattr(packet[packet.transport_layer], "dstport", 0) if hasattr(packet, "transport_layer") else 0

        # TCP flags if present
        flags = 0
        if hasattr(packet, "tcp"):
            flags = int(getattr(packet.tcp, "flags", 0), 16)

        features.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": int(src_port),
            "dst_port": int(dst_port),
            "protocol": proto,
            "packet_length": length,
            "inter_arrival_time": inter_time,
            "tcp_flags": flags
        })

    except Exception as e:
        continue  # skip malformed packets

# convert to DataFrame
df = pd.DataFrame(features)
if df.empty:
    print("❌ No features extracted. Check your pcap file.")
    exit()

print(f"✅ Extracted {len(df)} packets.")
print("🔹 Sample features:")
print(df.head())

# Save to CSV
df.to_csv(output_csv, index=False)
print(f"💾 Saved extracted features to {output_csv}")
