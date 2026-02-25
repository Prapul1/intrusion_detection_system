# app.py

from flask import Flask, render_template_string
from flask_socketio import SocketIO

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*")

HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>IDS Dashboard</title>
</head>
<body>
    <h2>Intrusion Detection System</h2>
    <h3>Status:</h3>
    <div id="alerts"></div>

    <script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
    <script>
        var socket = io("http://localhost:5050");

        socket.on("connect", function() {
            console.log("Connected to server");
        });

        socket.on("prediction", function(data) {
            console.log("Received in browser:", data);

            var div = document.getElementById("alerts");

            if (data.prediction == 1) {
                div.innerHTML += "<p style='color:red;font-weight:bold;'>⚠ ATTACK DETECTED (Prob: " 
                                 + data.probability.toFixed(2) + ")</p>";
            } else {
                div.innerHTML += "<p style='color:green;'>Normal Traffic (Prob: " 
                                 + data.probability.toFixed(2) + ")</p>";
            }
        });
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    return render_template_string(HTML)

@socketio.on("prediction")
def handle_prediction(data):
    print("Received prediction:", data)
    socketio.emit("prediction", data)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5050)