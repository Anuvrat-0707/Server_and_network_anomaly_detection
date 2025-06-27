import psutil
import time
import csv
import os
from datetime import datetime
from utils import detect_anomaly, detect_new_ips, detect_port_scan, get_top_apps
from shared.llm.llm_utils import explain_anomaly_via_llm
import joblib
import pandas as pd

LOG_FILE = 'data/log.csv'
seen_ips = set()

def init_csv():
    if not os.path.exists("data"):
        os.makedirs("data")
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode="w", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=[
                "timestamp", "cpu", "memory", "disk", "anomaly",
                "anomaly_type", "severity", "top_app_name", "explanation",
                "model_prediction", "model_class"
            ])
            writer.writeheader()

def log_data(data):  
    with open(LOG_FILE, 'a', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=data.keys())
        writer.writerow(data)

def main_loop():
    init_csv()

    binary_model = joblib.load("network_anomaly/models/binary_model.pkl")
    multi_model = joblib.load("network_anomaly/models/multiclass_model.pkl")

    print("📡 Starting anomaly detection loop...")
    while True:
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"📊 [{timestamp}] Monitoring...")

            cpu = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent

            anomaly, anomaly_type, severity = detect_anomaly(cpu, memory, disk)
            new_ip_detected = detect_new_ips(seen_ips)
            if new_ip_detected:
                print(f"🆕 New IP(s) detected: {new_ip_detected}")

            port_scan_detected = detect_port_scan()
            if port_scan_detected:
                print(f"🚨 Port scan activity from: {port_scan_detected}")

            top_apps = get_top_apps()
            metric_type = "memory"
            if anomaly_type:
                if "CPU" in anomaly_type:
                    metric_type = "cpu"
                elif "Memory" in anomaly_type:
                    metric_type = "memory"
                elif "Disk" in anomaly_type:
                    metric_type = "disk"

            top_app_data = top_apps.get(metric_type, {})
            top_app_name = top_app_data.get("name", "None")

            if anomaly:
                row = {
                    "cpu": cpu,
                    "memory": memory,
                    "disk": disk,
                    "anomaly_type": anomaly_type,
                    "top_app_name": top_app_name
                }
                explanation = explain_anomaly_via_llm(row)
            else:
                explanation = ""

            # Simulate sample input for ML model
            sample = pd.DataFrame([{
                "duration": 0,
                "protocol_type": 1,
                "service": 1,
                "flag": 1,
                "src_bytes": int(cpu * 100),
                "dst_bytes": int(memory * 100),
                "land": 0,
                "wrong_fragment": 0,
                "urgent": 0,
                "hot": 0,
                "num_failed_logins": 0,
                "logged_in": 1,
                "num_compromised": 0,
                "root_shell": 0,
                "su_attempted": 0,
                "num_root": 0,
                "num_file_creations": 0,
                "num_shells": 0,
                "num_access_files": 0,
                "num_outbound_cmds": 0,
                "is_host_login": 0,
                "is_guest_login": 0,
                "count": 1,
                "srv_count": 1,
                "serror_rate": 0,
                "srv_serror_rate": 0,
                "rerror_rate": 0,
                "srv_rerror_rate": 0,
                "same_srv_rate": 1,
                "diff_srv_rate": 0,
                "srv_diff_host_rate": 0,
                "dst_host_count": 1,
                "dst_host_srv_count": 1,
                "dst_host_same_srv_rate": 1,
                "dst_host_diff_srv_rate": 0,
                "dst_host_same_src_port_rate": 1,
                "dst_host_srv_diff_host_rate": 0,
                "dst_host_serror_rate": 0,
                "dst_host_srv_serror_rate": 0,
                "dst_host_rerror_rate": 0,
                "dst_host_srv_rerror_rate": 0
            }])

            # Predict using trained ML models
            binary_pred = int(binary_model.predict(sample)[0])
            multi_pred = str(multi_model.predict(sample)[0])

            # Log everything
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
                "model_prediction": binary_pred,
                "model_class": multi_pred
            })

        except Exception as e:
            print("⚠️ Error during monitoring:", e)

        time.sleep(5)

if __name__ == "__main__":
    main_loop()
