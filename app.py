# app.py
from flask import Flask, render_template
# 1. This import is new and fixes the error
from flask_socketio import SocketIO, emit
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

    # 2. This line is changed from 'socketio.emit' to just 'emit'
    emit('update_dashboard', payload, broadcast=True)

if __name__ == '__main__':
    print("🚀 Flask dashboard running on http://localhost:5000")
    # 3. This 'use_reloader=False' stops the server from restarting
    socketio.run(app, host='0.0.0.0', port=5000, debug=True, use_reloader=False)