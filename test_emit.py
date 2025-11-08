# test_emit.py
import socketio
import json
import time

sio = socketio.Client(logger=False, engineio_logger=False)
sio.connect('http://localhost:5000')

payload = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "prediction": ["attack", "normal", "attack"],   # example
    "meta": {"src":"test_emit"}
}

print("→ emitting test payload")
sio.emit("new_prediction", json.dumps(payload))
time.sleep(1)
sio.disconnect()
print("done")
