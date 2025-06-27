import pandas as pd
import joblib
import os
import csv
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

# === Paths ===
DATASET_PATH = "data/dataset/Train.txt"
LOG_PATH = "data/log.csv"
os.makedirs("data", exist_ok=True)

# === Define columns ===
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
           "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
           "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
           "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
           "is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
           "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
           "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
           "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate",
           "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "attack", "last_flag"]

# === Load dataset ===
print("📥 Loading dataset...")
df = pd.read_csv(DATASET_PATH, names=columns)

print("\n📋 Unique attack values in your file:")
print(df["attack"].value_counts())

# === Multiclass label mapping ===
def classify_attack(x):
    if x == "normal":
        return "normal"
    elif x in ["back", "land", "neptune", "pod", "smurf", "teardrop"]:
        return "DOS"
    elif x in ["ipsweep", "nmap", "portsweep", "satan"]:
        return "PROBE"
    elif x in ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster"]:
        return "R2L"
    elif x in ["buffer_overflow", "loadmodule", "perl", "rootkit"]:
        return "U2R"
    else:
        return "unknown"

df["attack_multi"] = df["attack"].apply(classify_attack)

# === Remove unknowns BEFORE generating binary labels ===
df = df[df["attack_multi"] != "unknown"]

# === Binary label after filtering
df["attack_binary"] = df["attack_multi"].apply(lambda x: 0 if x == "normal" else 1)

# === Show class distributions ===
print("🔍 Binary label counts:")
print(df["attack_binary"].value_counts())
print("\n🔍 Multiclass label counts (raw):")
print(df["attack_multi"].value_counts())

# === Encode categorical columns ===
cat_cols = ["protocol_type", "service", "flag"]
for col in cat_cols:
    df[col] = LabelEncoder().fit_transform(df[col])

# === Features and labels ===
X = df.drop(columns=["attack", "last_flag", "attack_binary", "attack_multi"])
y_bin = df["attack_binary"]
y_multi = df["attack_multi"]

# === Load trained models ===
print("📦 Loading trained models...")
binary_model = joblib.load("models/binary_model.pkl")
multi_model = joblib.load("models/multiclass_model.pkl")

# === Predict ===
print("🤖 Predicting...")
y_bin_pred = binary_model.predict(X)
y_multi_pred = multi_model.predict(X)

# === Evaluation ===
print("\n=== 📊 Binary Classification Report ===")
print(classification_report(
    y_bin, y_bin_pred,
    labels=[0, 1],
    target_names=["Normal", "Attack"],
    zero_division=0
))

print("\n=== 📊 Multiclass Classification Report ===")
print(classification_report(
    y_multi, y_multi_pred,
    zero_division=0
))

# === Log 5 samples to dashboard ===
print("📝 Logging 5 samples to dashboard...")
sample_indices = df.sample(n=5, random_state=42).index
with open(LOG_PATH, "a", newline='') as f:
    writer = csv.DictWriter(f, fieldnames=[
        "timestamp", "cpu", "memory", "disk", "anomaly",
        "anomaly_type", "severity", "top_app_name", "explanation",
        "model_prediction", "model_class"
    ])
    for idx in sample_indices:
        row = df.loc[idx]
        writer.writerow({
            "timestamp": "1999-01-01 00:00:00",
            "cpu": round(row["src_bytes"] / 1000, 2),
            "memory": round(row["dst_bytes"] / 1000, 2),
            "disk": round(row["count"] / 10, 2),
            "anomaly": int(row["attack_binary"]),
            "anomaly_type": "Historical - " + row["attack_multi"],
            "severity": "High" if row["attack_binary"] else "Low",
            "top_app_name": row["service"],
            "explanation": f"Historical sample classified as: {y_multi_pred[idx]}",
            "model_prediction": int(y_bin_pred[idx]),
            "model_class": y_multi_pred[idx]
        })

print("✅ Done. Open the dashboard to view logged results.")
