from flask import Flask, request, render_template_string, redirect, url_for
import hashlib
from collections import defaultdict
import datetime

app = Flask(__name__)

# Keywords to detect bomb threats
THREAT_KEYWORDS = [
    "bomb", "explosive", "detonate", "threat", "attack", "terrorist", "kill", "explode",
    "pipe bomb", "bomb threat", "detonation", "blast", "terrorism"
]

# In-memory storage
flagged_messages = []
behavior_profile = defaultdict(int)

# HTML + CSS Template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Bomb Threat Detection Demo</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f4f6f8;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 960px;
            margin: auto;
        }
        h1, h2 {
            color: #2c3e50;
        }
        form {
            background-color: #ffffff;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 4px 8px rgba(0,0,0,0.05);
            margin-bottom: 30px;
        }
        label {
            font-weight: 600;
            display: block;
            margin-top: 15px;
        }
        input, textarea {
            width: 100%;
            padding: 10px;
            margin-top: 6px;
            border: 1px solid #ccc;
            border-radius: 6px;
            font-size: 14px;
        }
        button {
            margin-top: 20px;
            background-color: #3498db;
            color: white;
            padding: 12px 20px;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }
        button:hover {
            background-color: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #ffffff;
            box-shadow: 0 4px 8px rgba(0,0,0,0.05);
        }
        th, td {
            padding: 12px 15px;
            border: 1px solid #ddd;
            text-align: left;
        }
        th {
            background-color: #2c3e50;
            color: white;
        }
        .high-risk {
            background-color: #ffe6e6;
        }
        .no-threat {
            font-style: italic;
            color: #888;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Bomb Threat Detection Demo</h1>
        <form method="post" action="{{ url_for('submit_message') }}">
            <label>Message Text:</label>
            <textarea name="message" rows="3" required></textarea>

            <label>Sender IP:</label>
            <input type="text" name="sender_ip" placeholder="e.g. 192.168.1.1" required>

            <label>Device ID:</label>
            <input type="text" name="device_id" placeholder="e.g. device123" required>

            <label>Account ID:</label>
            <input type="text" name="account_id" placeholder="e.g. user_abc" required>

            <label>Platform:</label>
            <input type="text" name="platform" placeholder="e.g. email, twitter" required>

            <button type="submit">Submit Message</button>
        </form>

        <h2>Flagged Threat Messages</h2>
        {% if flagged_messages %}
        <table>
            <tr>
                <th>Message</th>
                <th>Sender IP</th>
                <th>Device ID</th>
                <th>Account ID</th>
                <th>Platform</th>
                <th>Timestamp</th>
                <th>Device Fingerprint</th>
                <th>Risk Level</th>
            </tr>
            {% for msg in flagged_messages %}
            <tr class="{{ 'high-risk' if msg.risk_level == 'High' else '' }}">
                <td>{{ msg.message }}</td>
                <td>{{ msg.sender_ip }}</td>
                <td>{{ msg.device_id }}</td>
                <td>{{ msg.account_id }}</td>
                <td>{{ msg.platform }}</td>
                <td>{{ msg.timestamp }}</td>
                <td>{{ msg.device_fingerprint[:10] }}...</td>
                <td>{{ msg.risk_level }}</td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p class="no-threat">No threats flagged yet.</p>
        {% endif %}
    </div>
</body>
</html>
"""

def detect_threat(message):
    return any(kw in message.lower() for kw in THREAT_KEYWORDS)

def device_fingerprint(device_id, sender_ip):
    return hashlib.sha256((device_id + sender_ip).encode()).hexdigest()

@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_TEMPLATE, flagged_messages=flagged_messages)

@app.route("/submit_message", methods=["POST"])
def submit_message():
    message = request.form.get("message", "")
    sender_ip = request.form.get("sender_ip", "")
    device_id = request.form.get("device_id", "")
    account_id = request.form.get("account_id", "")
    platform = request.form.get("platform", "")
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    if detect_threat(message):
        fingerprint = device_fingerprint(device_id, sender_ip)
        behavior_profile[fingerprint] += 1
        count = behavior_profile[fingerprint]
        risk_level = "High" if count > 3 else "Medium"

        flagged_messages.append({
            "message": message,
            "sender_ip": sender_ip,
            "device_id": device_id,
            "account_id": account_id,
            "platform": platform,
            "timestamp": timestamp,
            "device_fingerprint": fingerprint,
            "risk_level": risk_level
        })

    return redirect(url_for("index"))

if __name__ == "__main__":
    app.run(debug=True)
