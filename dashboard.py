from flask import Flask, render_template, send_file, request, jsonify
import pandas as pd
import os
import joblib
import json
from sklearn.preprocessing import LabelEncoder
from utils import get_top_apps, get_recent_explanations
import win32evtlog

app = Flask(__name__)

NETWORK_MODELS_PATH = "network_anomaly/models/"
SERVER_LOG_PATH = "data/log.csv"
NETWORK_TEST_PATH = "data/dataset/Network_Test.txt"

COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
    "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
    "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
    "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "attack", "last_flag"
]

@app.route('/')
def home():
    datasets = os.listdir("data/dataset")
    return render_template("home.html", datasets=datasets)

@app.route('/dashboard/<dataset_name>')
def dashboard(dataset_name):
    dataset_path = os.path.join("data", "dataset", dataset_name)

    anomalies = get_recent_anomalies()
    top_apps = get_top_apps()
    event_logs = get_event_logs()
    explanations = get_recent_explanations()
    metrics = get_metrics()
    model_scores = get_model_scores()
    dataset_sample = get_dataset_sample(dataset_path)
    recent_dataset = get_recent_dataset_entries(dataset_path)

    return render_template("dashboard.html",
                           dataset_name=dataset_name,
                           anomalies=anomalies,
                           top_apps=top_apps,
                           event_logs=event_logs,
                           explanations=explanations,
                           metrics=metrics,
                           model_scores=model_scores,
                           dataset_sample=dataset_sample,
                           recent_dataset=recent_dataset)

@app.route('/download/<dataset_name>')
def download_dataset(dataset_name):
    dataset_path = os.path.join("data", "dataset", dataset_name)
    if os.path.exists(dataset_path):
        return send_file(dataset_path, as_attachment=True)
    return "Dataset not found", 404

def get_model_scores():
    try:
        with open("data/evaluation_scores.json", "r") as f:
            return json.load(f)
    except:
        return {
            "binary": {"accuracy": "-", "precision": "-", "recall": "-", "f1_score": "-"},
            "multiclass": {"accuracy": "-", "precision": "-", "recall": "-", "f1_score": "-"}
        }

def explain_prediction(row):
    reasons_bin = []
    reasons_multi = []

    if row['Binary_Prediction'] == 'Attack':
        if row.get('serror_rate', 0) > 0.5:
            reasons_bin.append("High SYN error rate")
        if row.get('rerror_rate', 0) > 0.5:
            reasons_bin.append("High REJ error rate")
        if row.get('src_bytes', 0) == 0 and row.get('dst_bytes', 0) == 0:
            reasons_bin.append("No data transferred")
        if row.get('logged_in', 1) == 0:
            reasons_bin.append("Unauthenticated access attempt")
    else:
        reasons_bin.append("Normal traffic")

    attack = row['Attack_Class']
    if attack == 'DOS':
        if row.get('count', 0) > 100 or row.get('serror_rate', 0) > 0.5:
            reasons_multi.append("High traffic volume or error rate")
    elif attack == 'PROBE':
        if row.get('srv_count', 0) > 50 or row.get('diff_srv_rate', 0) > 0.5:
            reasons_multi.append("Scanning behavior across multiple services")
    elif attack == 'R2L':
        if row.get('num_failed_logins', 0) > 0:
            reasons_multi.append("Failed login attempts detected")
    elif attack == 'U2R':
        if row.get('root_shell', 0) > 0 or row.get('num_file_creations', 0) > 0:
            reasons_multi.append("Privilege escalation or file access")
    elif attack == 'normal':
        reasons_multi.append("Normal behavior")

    return "; ".join(reasons_bin), "; ".join(reasons_multi)

def get_dataset_sample(path, limit=100):
    try:
        df = pd.read_csv(path, names=COLUMNS).head(limit)
        for col in ["protocol_type", "service", "flag"]:
            df[col] = LabelEncoder().fit_transform(df[col])
        X = df.drop(columns=["attack", "last_flag"])

        binary_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "binary_model.pkl"))
        multiclass_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "multiclass_model.pkl"))

        df["Binary_Prediction"] = ["Normal" if p == 0 else "Attack" for p in binary_model.predict(X)]
        df["Attack_Class"] = multiclass_model.predict(X)

        explanations = [explain_prediction(row) for _, row in df.iterrows()]
        df["Explanation_Binary"] = [e[0] for e in explanations]
        df["Explanation_Multi"] = [e[1] for e in explanations]

        display_cols = [
            "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
            "logged_in", "count", "srv_count", "attack", "last_flag",
            "Binary_Prediction", "Attack_Class", "Explanation_Binary", "Explanation_Multi"
        ]
        return df[display_cols].to_dict(orient="records")
    except Exception as e:
        print("⚠️ Error loading sample:", e)
        return []

def get_recent_dataset_entries(path, limit=10):
    try:
        df = pd.read_csv(path, names=COLUMNS).tail(limit)
        for col in ["protocol_type", "service", "flag"]:
            df[col] = LabelEncoder().fit_transform(df[col])
        X = df.drop(columns=["attack", "last_flag"])

        binary_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "binary_model.pkl"))
        multiclass_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "multiclass_model.pkl"))

        df["Binary_Prediction"] = ["Normal" if p == 0 else "Attack" for p in binary_model.predict(X)]
        df["Attack_Class"] = multiclass_model.predict(X)

        explanations = [explain_prediction(row) for _, row in df.iterrows()]
        df["Explanation_Binary"] = [e[0] for e in explanations]
        df["Explanation_Multi"] = [e[1] for e in explanations]

        return df.to_dict(orient="records")
    except Exception as e:
        print("⚠️ Error loading recent entries:", e)
        return []

def get_recent_anomalies(limit=10):
    try:
        df = pd.read_csv(SERVER_LOG_PATH)
        if "anomaly" not in df.columns:
            return []
        return df[df["anomaly"] == 1].sort_values("timestamp", ascending=False).head(limit).to_dict(orient="records")
    except Exception as e:
        print("⚠️ Error loading anomalies:", e)
        return []

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

def get_metrics():
    try:
        df = pd.read_csv(SERVER_LOG_PATH).tail(100)
        return {
            'cpu': df['cpu'].tolist(),
            'memory': df['memory'].tolist(),
            'disk': df['disk'].tolist(),
            'timestamp': df['timestamp'].tolist()
        }
    except:
        return {'cpu': [], 'memory': [], 'disk': [], 'timestamp': []}

if __name__ == "__main__":
    app.run(debug=True)
