import pyshark
import pandas as pd

# Path to your capture file (update if needed)
pcap_path = r"C:\Users\PRAPUL U\Desktop\capture.pcapng"
output_csv = "data/live_capture.csv"

print("🚀 Reading capture file...")
cap = pyshark.FileCapture(pcap_path, only_summaries=True)

packets = []
for packet in cap:
    packets.append({
        "No": packet.no,
        "Time": packet.time,
        "Source": packet.source,
        "Destination": packet.destination,
        "Protocol": packet.protocol,
        "Length": packet.length,
        "Info": packet.info
    })

cap.close()

# Convert to DataFrame
df = pd.DataFrame(packets)
df.to_csv(output_csv, index=False)

print(f"✅ Capture converted successfully! Saved as {output_csv}")
print(df.head())
