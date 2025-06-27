# server_anomaly/main_server.py

import psutil
import time
import csv
import os
import sys
from datetime import datetime

# ✅ Add parent directory to sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

# ✅ Correct imports after path fix
from utils_server import detect_anomaly, get_top_apps
from shared.llm.llm_utils import explain_anomaly_via_llm

LOG_FILE = 'data/server_log.csv'

def init_csv():
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=[
                "timestamp", "cpu", "memory", "disk", "anomaly",
                "anomaly_type", "severity", "top_app_name", "explanation", "model_prediction", "model_class"

            ])
            writer.writeheader()

def log_data(data):
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writerow(data)

def main_loop():
    init_csv()
    print("🖥️ Starting SERVER anomaly detection loop...")

    while True:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent

            anomaly, anomaly_type, severity = detect_anomaly(cpu, memory, disk)

            top_apps = get_top_apps()
            metric_type = "memory"
            if "CPU" in str(anomaly_type):
                metric_type = "cpu"
            elif "Disk" in str(anomaly_type):
                metric_type = "disk"

            top_app_data = top_apps.get(metric_type, {})
            top_app_name = top_app_data.get("name", "None")

            explanation = ""
            if anomaly:
                row = {
                    "cpu": cpu,
                    "memory": memory,
                    "disk": disk,
                    "anomaly_type": anomaly_type,
                    "top_app_name": top_app_name
                }
                explanation = explain_anomaly_via_llm(row)

            log_data({
                "timestamp": timestamp,
                "cpu": cpu,
                "memory": memory,
                "disk": disk,
                "anomaly": int(anomaly),
                "anomaly_type": anomaly_type if anomaly else "None",
                "severity": severity if anomaly else "None",
                "top_app_name": top_app_name,
                "explanation": explanation,
                "model_prediction": 0,  # or actual prediction if available
                "model_class": "normal"  # or actual class if integrated
            })


        except Exception as e:
            print("⚠️ SERVER Monitoring Error:", e)

        time.sleep(5)

if __name__ == "__main__":
    main_loop()
