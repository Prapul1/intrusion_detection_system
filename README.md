# Flow-Based Intrusion Detection System (ML-Based)

A real-time Intrusion Detection System built using flow-level traffic features and LightGBM.

## Architecture

Packet Capture (TShark)
→ Flow Aggregation (Python)
→ Feature Engineering
→ LightGBM Model
→ Real-Time Dashboard (Flask + SocketIO)

## Features

- Flow-based behavioral analysis
- Real-time traffic monitoring
- Machine Learning detection (Binary Classification)
- Continuous monitoring loop
- Live web dashboard alerts

## Technologies Used

- Python
- LightGBM
- Flask
- SocketIO
- PyShark
- Wireshark (TShark)

## How To Run

1. Install dependencies:
   pip install -r requirements.txt

2. Train model:
   python train_ids.py

3. Start dashboard:
   python app.py

4. Run detector:
   python detector.py

## Notes

- Requires Wireshark installed.
- Requires admin privileges for packet capture.
- Model trained on CICIDS dataset.