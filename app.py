# app.py
from flask import Flask, render_template
from flask_socketio import SocketIO
import json

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

live_data = []

@app.route('/')
def index():
    return render_template('dashboard.html')

@socketio.on('new_prediction')
def handle_new_prediction(data):
    # Accept either JSON string or dict
    if isinstance(data, str):
        try:
            payload = json.loads(data)
        except Exception:
            print("⚠️ Received non-json string:", data)
            return
    else:
        payload = data

    live_data.append(payload)
    print("📊 New data received:", payload)

    # Emit update to connected clients (don't use broadcast kwarg; not supported in some versions)
    socketio.emit('update_dashboard', payload)

if __name__ == '__main__':
    print("🚀 Flask dashboard running on http://localhost:5000")
    # use eventlet/gevent if available for better concurrency; this will work with default dev server too
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
