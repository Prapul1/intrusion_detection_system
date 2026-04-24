# app.py — SOC Dashboard with MITRE ATT&CK Integration

from flask import Flask, render_template_string
from flask_socketio import SocketIO, emit

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<title>SOC · IDS Dashboard</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.socket.io/4.5.4/socket.io.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  :root {
    --bg:       #080c10;
    --surface:  #0d1117;
    --border:   #1a2332;
    --accent:   #00ffe0;
    --red:      #ff3b5c;
    --orange:   #ff9f1c;
    --green:    #00ff88;
    --muted:    #4a6070;
    --text:     #c9d8e8;
    --mono:     'Share Tech Mono', monospace;
    --sans:     'Rajdhani', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Scanline overlay */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background: repeating-linear-gradient(
      0deg,
      transparent,
      transparent 2px,
      rgba(0,255,224,0.015) 2px,
      rgba(0,255,224,0.015) 4px
    );
    pointer-events: none;
    z-index: 1000;
  }

  /* ── Header ── */
  header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 14px 28px;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
    position: sticky;
    top: 0;
    z-index: 100;
  }

  .logo {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .logo-icon {
    width: 36px;
    height: 36px;
    border: 2px solid var(--accent);
    border-radius: 6px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-family: var(--mono);
    font-size: 16px;
    color: var(--accent);
    animation: pulse-border 3s infinite;
  }

  @keyframes pulse-border {
    0%, 100% { box-shadow: 0 0 0px var(--accent); }
    50%       { box-shadow: 0 0 12px var(--accent); }
  }

  .logo-text {
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 2px;
    color: white;
    text-transform: uppercase;
  }

  .logo-sub {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    letter-spacing: 1px;
  }

  .header-right {
    display: flex;
    align-items: center;
    gap: 20px;
  }

  .conn-badge {
    display: flex;
    align-items: center;
    gap: 8px;
    font-family: var(--mono);
    font-size: 12px;
    color: var(--muted);
  }

  .conn-dot {
    width: 8px; height: 8px;
    border-radius: 50%;
    background: var(--muted);
    transition: background 0.3s;
  }
  .conn-dot.live { background: var(--green); box-shadow: 0 0 8px var(--green); }

  .clock {
    font-family: var(--mono);
    font-size: 13px;
    color: var(--accent);
    letter-spacing: 1px;
  }

  /* ── Grid ── */
  .grid {
    display: grid;
    grid-template-columns: 280px 1fr 1fr;
    grid-template-rows: auto auto auto;
    gap: 1px;
    background: var(--border);
    min-height: calc(100vh - 61px);
  }

  .panel {
    background: var(--surface);
    padding: 20px;
    position: relative;
  }

  .panel-title {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 16px;
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .panel-title::before {
    content: '';
    display: inline-block;
    width: 3px; height: 12px;
    background: var(--accent);
  }

  /* ── Stat cards ── */
  .stats-col {
    grid-row: 1 / 4;
    display: flex;
    flex-direction: column;
    gap: 1px;
    background: var(--border);
  }

  .stat-card {
    background: var(--surface);
    padding: 20px;
    flex: 1;
  }

  .stat-label {
    font-family: var(--mono);
    font-size: 10px;
    letter-spacing: 2px;
    color: var(--muted);
    text-transform: uppercase;
    margin-bottom: 8px;
  }

  .stat-value {
    font-family: var(--mono);
    font-size: 36px;
    font-weight: bold;
    color: var(--accent);
    line-height: 1;
    transition: color 0.3s;
  }

  .stat-value.danger { color: var(--red); }
  .stat-value.warn   { color: var(--orange); }

  .stat-sub {
    font-size: 11px;
    color: var(--muted);
    margin-top: 6px;
    font-family: var(--mono);
  }

  /* Threat level bar */
  .threat-bar-wrap {
    margin-top: 10px;
    height: 4px;
    background: var(--border);
    border-radius: 2px;
    overflow: hidden;
  }

  .threat-bar {
    height: 100%;
    width: 0%;
    background: var(--accent);
    border-radius: 2px;
    transition: width 0.8s ease, background 0.3s;
  }

  /* ── Charts ── */
  .chart-panel { position: relative; }
  canvas { max-height: 180px; width: 100% !important; }

  /* ── MITRE panel ── */
  .mitre-panel {
    grid-column: 2 / 4;
  }

  .mitre-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 10px;
  }

  .mitre-card {
    border: 1px solid var(--border);
    border-radius: 6px;
    padding: 12px;
    position: relative;
    overflow: hidden;
    transition: border-color 0.3s, transform 0.2s;
    cursor: default;
  }

  .mitre-card:hover {
    transform: translateY(-2px);
    border-color: var(--accent);
  }

  .mitre-card::before {
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
  }

  .mitre-card.severity-critical::before { background: var(--red); }
  .mitre-card.severity-high::before     { background: var(--orange); }
  .mitre-card.severity-medium::before   { background: var(--accent); }

  .mitre-card.hit {
    animation: mitre-flash 1s ease;
  }

  @keyframes mitre-flash {
    0%   { background: rgba(255,59,92,0.15); border-color: var(--red); }
    100% { background: transparent; }
  }

  .mitre-id {
    font-family: var(--mono);
    font-size: 11px;
    color: var(--accent);
    margin-bottom: 4px;
  }

  .mitre-name {
    font-size: 13px;
    font-weight: 600;
    color: white;
    margin-bottom: 4px;
    line-height: 1.3;
  }

  .mitre-tactic {
    font-family: var(--mono);
    font-size: 10px;
    color: var(--muted);
    margin-bottom: 8px;
  }

  .mitre-count {
    font-family: var(--mono);
    font-size: 22px;
    font-weight: bold;
    color: var(--text);
  }

  .mitre-count.active { color: var(--red); }

  .severity-badge {
    display: inline-block;
    font-family: var(--mono);
    font-size: 9px;
    letter-spacing: 1px;
    padding: 2px 6px;
    border-radius: 3px;
    text-transform: uppercase;
    margin-top: 6px;
  }

  .severity-badge.critical { background: rgba(255,59,92,0.15); color: var(--red); }
  .severity-badge.high     { background: rgba(255,159,28,0.15); color: var(--orange); }
  .severity-badge.medium   { background: rgba(0,255,224,0.1);   color: var(--accent); }

  /* ── Event feed ── */
  .feed-panel { grid-column: 2 / 4; }

  #events {
    height: 180px;
    overflow-y: auto;
    font-family: var(--mono);
    font-size: 12px;
    line-height: 1.8;
  }

  #events::-webkit-scrollbar { width: 4px; }
  #events::-webkit-scrollbar-track { background: var(--bg); }
  #events::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }

  .event-line {
    display: flex;
    gap: 12px;
    padding: 3px 6px;
    border-radius: 3px;
    animation: fade-in 0.3s ease;
  }

  @keyframes fade-in {
    from { opacity: 0; transform: translateX(-8px); }
    to   { opacity: 1; transform: translateX(0); }
  }

  .event-line:hover { background: rgba(255,255,255,0.03); }
  .event-line.high   { border-left: 2px solid var(--red); }
  .event-line.medium { border-left: 2px solid var(--orange); }

  .event-time  { color: var(--muted); min-width: 80px; }
  .event-level { min-width: 70px; }
  .event-level.high   { color: var(--red); }
  .event-level.medium { color: var(--orange); }
  .event-prob  { color: var(--text); min-width: 80px; }
  .event-mitre { color: var(--accent); }

  .placeholder { color: var(--muted); font-size: 12px; font-family: var(--mono); padding: 8px; }
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">⬡</div>
    <div>
      <div class="logo-text">IDS · SOC Console</div>
      <div class="logo-sub">ML-POWERED · MITRE ATT&CK MAPPED</div>
    </div>
  </div>
  <div class="header-right">
    <div class="conn-badge">
      <div class="conn-dot" id="connDot"></div>
      <span id="connStatus">OFFLINE</span>
    </div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<div class="grid">

  <!-- ── Left stats column ── -->
  <div class="stats-col">
    <div class="stat-card">
      <div class="stat-label">Flows / Window</div>
      <div class="stat-value" id="flows">0</div>
      <div class="stat-sub">last capture window</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Avg Risk Score</div>
      <div class="stat-value" id="avgProb">0.000</div>
      <div class="threat-bar-wrap">
        <div class="threat-bar" id="threatBar"></div>
      </div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Max Risk Score</div>
      <div class="stat-value" id="maxProb">0.000</div>
      <div class="stat-sub">peak this window</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High Risk Flows</div>
      <div class="stat-value danger" id="highRisk">0</div>
      <div class="stat-sub">above threshold</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Total Alerts</div>
      <div class="stat-value warn" id="totalAlerts">0</div>
      <div class="stat-sub">since session start</div>
    </div>
  </div>

  <!-- ── Risk chart ── -->
  <div class="panel chart-panel">
    <div class="panel-title">Average Risk Over Time</div>
    <canvas id="riskChart"></canvas>
  </div>

  <!-- ── Attack chart ── -->
  <div class="panel chart-panel">
    <div class="panel-title">High Risk Events / Window</div>
    <canvas id="attackChart"></canvas>
  </div>

  <!-- ── MITRE ATT&CK panel ── -->
  <div class="panel mitre-panel">
    <div class="panel-title">MITRE ATT&CK · Detection Coverage</div>
    <div class="mitre-grid" id="mitreGrid"></div>
  </div>

  <!-- ── Live event feed ── -->
  <div class="panel feed-panel">
    <div class="panel-title">Live Detection Feed</div>
    <div id="events">
      <div class="placeholder">// Waiting for traffic analysis...</div>
    </div>
  </div>

</div>

<script>
// ── Clock ────────────────────────────────────────────────────────────────────
function updateClock() {
  document.getElementById("clock").innerText = new Date().toLocaleTimeString();
}
setInterval(updateClock, 1000);
updateClock();

// ── Socket ───────────────────────────────────────────────────────────────────
var socket = io();
var totalAlerts = 0;

socket.on("connect", function() {
  document.getElementById("connDot").classList.add("live");
  document.getElementById("connStatus").innerText = "LIVE";
});

socket.on("disconnect", function() {
  document.getElementById("connDot").classList.remove("live");
  document.getElementById("connStatus").innerText = "OFFLINE";
});

// ── Charts ───────────────────────────────────────────────────────────────────
const chartDefaults = {
  animation: false,
  responsive: true,
  plugins: { legend: { labels: { color: "#4a6070", font: { family: "Share Tech Mono", size: 11 } } } },
  scales: {
    y: { ticks: { color: "#4a6070", font: { family: "Share Tech Mono", size: 10 } }, grid: { color: "#1a2332" } },
    x: { ticks: { color: "#4a6070", font: { family: "Share Tech Mono", size: 10 } }, grid: { color: "#1a2332" } }
  }
};

var riskChart = new Chart(document.getElementById("riskChart"), {
  type: "line",
  data: {
    labels: [],
    datasets: [{
      label: "avg risk",
      data: [],
      borderColor: "#00ffe0",
      backgroundColor: "rgba(0,255,224,0.05)",
      fill: true,
      tension: 0.4,
      pointRadius: 3,
      pointBackgroundColor: "#00ffe0"
    }]
  },
  options: { ...chartDefaults, scales: { ...chartDefaults.scales, y: { ...chartDefaults.scales.y, min: 0, max: 1 } } }
});

var attackChart = new Chart(document.getElementById("attackChart"), {
  type: "bar",
  data: {
    labels: [],
    datasets: [{
      label: "high risk count",
      data: [],
      backgroundColor: "rgba(255,59,92,0.6)",
      borderColor: "#ff3b5c",
      borderWidth: 1
    }]
  },
  options: chartDefaults
});

const MAX_POINTS = 20;

function pushChart(chart, label, value) {
  chart.data.labels.push(label);
  chart.data.datasets[0].data.push(value);
  if (chart.data.labels.length > MAX_POINTS) {
    chart.data.labels.shift();
    chart.data.datasets[0].data.shift();
  }
  chart.update();
}

// ── MITRE ATT&CK Grid ────────────────────────────────────────────────────────
const TECHNIQUES = {
  "T1046": { name: "Network Service Discovery", tactic: "Discovery",          severity: "medium",   url: "https://attack.mitre.org/techniques/T1046" },
  "T1595": { name: "Active Scanning",           tactic: "Reconnaissance",     severity: "high",     url: "https://attack.mitre.org/techniques/T1595" },
  "T1041": { name: "Exfiltration Over C2",      tactic: "Exfiltration",       severity: "critical", url: "https://attack.mitre.org/techniques/T1041" },
  "T1571": { name: "Non-Standard Port",         tactic: "Command & Control",  severity: "high",     url: "https://attack.mitre.org/techniques/T1571" },
  "T1498": { name: "Network DoS",               tactic: "Impact",             severity: "critical", url: "https://attack.mitre.org/techniques/T1498" },
  "T1110": { name: "Brute Force",               tactic: "Credential Access",  severity: "high",     url: "https://attack.mitre.org/techniques/T1110" },
  "T1048": { name: "Exfil Alt Protocol",        tactic: "Exfiltration",       severity: "critical", url: "https://attack.mitre.org/techniques/T1048" },
  "T1071": { name: "App Layer Protocol C2",     tactic: "Command & Control",  severity: "high",     url: "https://attack.mitre.org/techniques/T1071" },
};

var mitreCounts = {};
Object.keys(TECHNIQUES).forEach(id => mitreCounts[id] = 0);

// Build the grid cards
var grid = document.getElementById("mitreGrid");
Object.entries(TECHNIQUES).forEach(([id, t]) => {
  var card = document.createElement("a");
  card.href = t.url;
  card.target = "_blank";
  card.id = "mitre-" + id;
  card.className = "mitre-card severity-" + t.severity;
  card.style.textDecoration = "none";
  card.innerHTML = `
    <div class="mitre-id">${id}</div>
    <div class="mitre-name">${t.name}</div>
    <div class="mitre-tactic">${t.tactic}</div>
    <div class="mitre-count" id="count-${id}">0</div>
    <div class="severity-badge ${t.severity}">${t.severity}</div>
  `;
  grid.appendChild(card);
});

function triggerMitre(techniqueId) {
  if (!techniqueId || !TECHNIQUES[techniqueId]) return;
  mitreCounts[techniqueId]++;
  var countEl = document.getElementById("count-" + techniqueId);
  if (countEl) {
    countEl.innerText = mitreCounts[techniqueId];
    countEl.classList.add("active");
  }
  var card = document.getElementById("mitre-" + techniqueId);
  if (card) {
    card.classList.remove("hit");
    void card.offsetWidth; // reflow to restart animation
    card.classList.add("hit");
  }
}

// ── Socket Events ─────────────────────────────────────────────────────────────
socket.on("window_update", function(data) {
  document.getElementById("flows").innerText    = data.window_flows;
  document.getElementById("avgProb").innerText  = data.avg_probability.toFixed(3);
  document.getElementById("maxProb").innerText  = data.max_probability.toFixed(3);
  document.getElementById("highRisk").innerText = data.high_risk_count;

  // Colour avg risk by severity
  var avgEl = document.getElementById("avgProb");
  avgEl.className = "stat-value";
  if (data.avg_probability > 0.7)      avgEl.classList.add("danger");
  else if (data.avg_probability > 0.4) avgEl.classList.add("warn");

  // Threat bar
  var bar = document.getElementById("threatBar");
  bar.style.width = (data.avg_probability * 100) + "%";
  bar.style.background = data.avg_probability > 0.7 ? "var(--red)"
                       : data.avg_probability > 0.4 ? "var(--orange)"
                       : "var(--accent)";

  var t = new Date().toLocaleTimeString();
  pushChart(riskChart, t, data.avg_probability);
  pushChart(attackChart, t, data.high_risk_count);
});

socket.on("prediction", function(data) {
  totalAlerts++;
  document.getElementById("totalAlerts").innerText = totalAlerts;

  var feed = document.getElementById("events");
  var placeholder = feed.querySelector(".placeholder");
  if (placeholder) placeholder.remove();

  var t = new Date().toLocaleTimeString();
  var techId  = data.technique_id  || "";
  var techName = data.technique_name || "";

  var line = document.createElement("div");
  line.className = "event-line " + data.risk_level;
  line.innerHTML =
    `<span class="event-time">${t}</span>` +
    `<span class="event-level ${data.risk_level}">${data.risk_level.toUpperCase()}</span>` +
    `<span class="event-prob">prob: ${data.probability.toFixed(3)}</span>` +
    (techId ? `<span class="event-mitre">${techId} · ${techName}</span>` : "");

  feed.appendChild(line);

  // Keep max 200 lines
  while (feed.children.length > 200) feed.removeChild(feed.firstChild);
  feed.scrollTop = feed.scrollHeight;

  if (techId) triggerMitre(techId);
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
    emit("prediction", data, broadcast=True)

@socketio.on("window_update")
def handle_window_update(data):
    emit("window_update", data, broadcast=True)

if __name__ == "__main__":
    socketio.run(app, host="0.0.0.0", port=5050, debug=False)