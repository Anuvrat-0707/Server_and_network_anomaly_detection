from flask import Flask, render_template, send_file
import pandas as pd
import os
import win32evtlog
from utils_server import get_top_apps

app = Flask(__name__)
SERVER_LOG_PATH = "../data/log.csv"



@app.route("/")
def dashboard():
    try:
        df = pd.read_csv(SERVER_LOG_PATH)

        explanations = df[df["anomaly"] == 1].sort_values("timestamp", ascending=False).to_dict(orient="records")
        top_apps = {
            "cpu": {"name": df.iloc[-1]["top_app_name"], "value": df.iloc[-1]["cpu"]},
            "memory": {"name": df.iloc[-1]["top_app_name"], "value": df.iloc[-1]["memory"]},
            "disk": {"name": df.iloc[-1]["top_app_name"], "value": df.iloc[-1]["disk"]}
        }
        metrics = {
            "timestamp": df["timestamp"].tolist(),
            "cpu": df["cpu"].tolist(),
            "memory": df["memory"].tolist(),
            "disk": df["disk"].tolist()
        }

        event_logs = get_event_logs()

        return render_template("dashboard.html",
                               dataset_name="log.csv",
                               top_apps=top_apps,
                               explanations=explanations,
                               event_logs=event_logs,
                               metrics=metrics,
                               dataset_sample=[],
                               recent_dataset=[],
                               model_scores={"binary": {}, "multiclass": {}})
    except Exception as e:
        print("Error rendering dashboard:", e)
        return f"Error loading dashboard: {e}"

@app.route("/download/log.csv")
def download_log():
    return send_file(SERVER_LOG_PATH, as_attachment=True)

def get_event_logs(max_logs=10):
    logs = []
    try:
        hand = win32evtlog.OpenEventLog('localhost', 'System')
        flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        total = 0
        while total < max_logs:
            events = win32evtlog.ReadEventLog(hand, flags, 0)
            if not events:
                break
            for ev in events:
                logs.append({
                    'time': ev.TimeGenerated.strftime("%Y-%m-%d %H:%M:%S"),
                    'source': ev.SourceName,
                    'event_id': ev.EventID,
                    'message': str(ev.StringInserts)
                })
                total += 1
    except Exception as e:
        logs.append({'time': 'N/A', 'source': 'Error', 'event_id': 0, 'message': str(e)})
    return logs

if __name__ == "__main__":
    app.run(debug=True, port=5000)
