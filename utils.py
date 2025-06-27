import psutil
import socket
import time
from collections import defaultdict
import csv

previous_connections = set()
port_scan_tracker = defaultdict(int)
port_scan_window = 10  # seconds
port_threshold = 10  # number of ports hit in short time

def detect_anomaly(cpu, memory, disk):
    if cpu > 85:
        return True, "High CPU Usage", "High"
    elif memory > 85:
        return True, "High Memory Usage", "Medium"
    elif disk > 90:
        return True, "High Disk Usage", "Medium"
    return False, None, None

def get_top_apps():
    top = {"cpu": ("N/A", 0), "memory": ("N/A", 0), "disk": ("N/A", 0)}

    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
        try:
            name = proc.info['name']
            cpu = proc.info['cpu_percent']
            memory = proc.info['memory_percent']

            if cpu > top["cpu"][1]:
                top["cpu"] = (name, cpu)
            if memory > top["memory"][1]:
                top["memory"] = (name, memory)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    disk_usage = psutil.disk_usage('/')
    top["disk"] = ("Disk IO", disk_usage.percent)

    return {
        "cpu": {"name": top["cpu"][0], "value": round(top["cpu"][1], 2)},
        "memory": {"name": top["memory"][0], "value": round(top["memory"][1], 2)},
        "disk": {"name": top["disk"][0], "value": round(top["disk"][1], 2)}
    }

def detect_new_ips(seen_ips):
    new_ips = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family.name == 'AF_INET':
                ip = addr.address
                if ip not in seen_ips:
                    new_ips.append(ip)
                    seen_ips.add(ip)
    return new_ips

def detect_port_scan():
    global port_scan_tracker
    suspicious_ips = []

    for conn in psutil.net_connections(kind='inet'):
        if conn.raddr:
            ip = conn.raddr.ip
            port_scan_tracker[ip] += 1

    now = time.time()
    for ip, count in list(port_scan_tracker.items()):
        if count > port_threshold:
            suspicious_ips.append(ip)
            del port_scan_tracker[ip]  # reset after detection

    return suspicious_ips

def get_recent_explanations(csv_path="data/log.csv", limit=10):
    explanations = []
    try:
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            for row in rows[-limit:]:
                explanations.append({
                    "timestamp": row.get("timestamp", ""),
                    "anomaly_type": row.get("anomaly_type", ""),
                    "severity": row.get("severity", ""),
                    "top_app_name": row.get("top_app_name", ""),
                    "explanation": row.get("explanation", "N/A"),
                    "model_prediction": row.get("model_prediction", "N/A"),
                    "model_class": row.get("model_class", "N/A")
                })
    except Exception as e:
        print("⚠️ Error reading recent explanations:", e)

    return explanations

