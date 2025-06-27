from flask import Flask, render_template, send_file, request
import pandas as pd
import os
import json
import joblib
from sklearn.preprocessing import LabelEncoder
from utils_network import detect_new_ips, detect_port_scan

app = Flask(__name__)

# === Paths ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_DIR = os.path.join(BASE_DIR, "..", "data", "dataset")
NETWORK_MODELS_PATH = os.path.join(BASE_DIR, "models")
EVAL_PATH = os.path.join(BASE_DIR, "..", "data", "evaluation_scores.json")

# === Column Names (as per dataset) ===
COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
    "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
    "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
    "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
    "attack", "last_flag"
]

DISPLAY_COLUMNS = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "logged_in",
    "count", "srv_count", "attack", "last_flag", "Binary_Prediction", "Attack_Class",
    "Explanation_Binary", "Explanation_Multi"
]

# === Routes ===

@app.route('/')
def home():
    if not os.path.exists(DATASET_DIR):
        return "Dataset folder not found. Please make sure 'data/dataset/' exists."
    datasets = [f for f in os.listdir(DATASET_DIR) if f.endswith(".txt")]
    return render_template("home.html", datasets=datasets)

@app.route('/dashboard/<dataset_name>')
def dashboard(dataset_name):
    dataset_path = os.path.join(DATASET_DIR, dataset_name)

    model_scores = get_model_scores()
    dataset_sample = get_dataset_sample(dataset_path)
    recent_dataset = get_recent_dataset_entries(dataset_path)

    new_ips = detect_new_ips()
    port_scanners = detect_port_scan()

    return render_template("dashboard.html",
                           dataset_name=dataset_name,
                           anomalies=port_scanners,
                           top_apps=new_ips,
                           event_logs=None,
                           explanations=None,
                           metrics=None,
                           model_scores=model_scores,
                           dataset_sample=dataset_sample,
                           recent_dataset=recent_dataset)

@app.route('/download/<dataset_name>')
def download_dataset(dataset_name):
    dataset_path = os.path.join(DATASET_DIR, dataset_name)
    if os.path.exists(dataset_path):
        return send_file(dataset_path, as_attachment=True)
    return "Dataset not found", 404

@app.route('/predict_manual', methods=['POST'])
def predict_manual():
    try:
        input_data = request.form.to_dict()
        df = pd.DataFrame([input_data])

        for col in df.columns:
            df[col] = pd.to_numeric(df[col])

        binary_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "binary_model.pkl"))
        multi_model = joblib.load(os.path.join(NETWORK_MODELS_PATH, "multiclass_model.pkl"))

        binary_pred = binary_model.predict(df)[0]
        multi_pred = multi_model.predict(df)[0]

        return render_template("predict_result.html",
                               input_data=input_data,
                               binary_pred="Attack" if binary_pred else "Normal",
                               multi_pred=multi_pred)

    except Exception as e:
        return f"❌ Error in prediction: {e}", 500


# === Utility Functions ===

def get_model_scores():
    try:
        with open(EVAL_PATH, "r") as f:
            return json.load(f)
    except:
        return {
            "binary": {"accuracy": "-", "precision": "-", "recall": "-", "f1_score": "-"},
            "multiclass": {"accuracy": "-", "precision": "-", "recall": "-", "f1_score": "-"}
        }

def explain_prediction(row):
    if row['Binary_Prediction'] == 'Attack':
        binary_exp = (
            f"The connection was classified as an **attack** because of unusual patterns such as "
            f"high source bytes ({row['src_bytes']}), service type '{row['service']}', and flag '{row['flag']}'. "
            f"The protocol used was '{row['protocol_type']}', which, in combination with login status ({'logged in' if row['logged_in'] else 'not logged in'}), "
            f"suggests potentially malicious behavior."
        )
    else:
        binary_exp = (
            f"The connection was classified as **normal**. The values of source bytes ({row['src_bytes']}), service type '{row['service']}', "
            f"and protocol '{row['protocol_type']}' are within expected ranges. Also, the login status "
            f"({ 'logged in' if row['logged_in'] else 'not logged in' }) supports normal activity."
        )

    attack_class = row['Attack_Class']
    if attack_class.lower() == "normal":
        multi_exp = "No attack type detected. This connection exhibits features consistent with legitimate network behavior."
    else:
        multi_exp = (
            f"The model identified this connection as '{attack_class.upper()}' attack due to characteristics like service: '{row['service']}', "
            f"flag: '{row['flag']}', and high frequency counts (count: {row['count']}, srv_count: {row['srv_count']}). "
            f"These features align with patterns seen in historical '{attack_class}' attacks."
        )

    return binary_exp, multi_exp

def get_dataset_sample(path, limit=100):
    try:
        df = pd.read_csv(path, names=COLUMNS).head(limit)
        label_encoders = {}

        for col in ["protocol_type", "service", "flag"]:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col])
            label_encoders[col] = le

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
        print("⚠️ Error loading recent dataset entries:", e)
        return []

# === Run the App ===
if __name__ == "__main__":
    app.run(debug=True, port=5002)
