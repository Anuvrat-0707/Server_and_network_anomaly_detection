import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib
import os
import json
from sklearn.metrics import precision_score, recall_score, f1_score


# ==== Configuration ====
TEST_PATH = "data/dataset/Train.txt"  # Update if your path differs
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

# ==== Load and preprocess data ====
df = pd.read_csv(TEST_PATH, names=COLUMNS)

# Encode categorical columns
for col in ["protocol_type", "service", "flag"]:
    df[col] = LabelEncoder().fit_transform(df[col])

# Define binary labels
df['Binary_Label'] = df['attack'].apply(lambda x: 0 if x == 'normal' else 1)

# Define multiclass labels (group similar attacks)
def map_attack_type(name):
    name = name.lower()
    if name in ['back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'mailbomb', 'apache2', 'processtable', 'udpstorm']:
        return 'DOS'
    elif name in ['ipsweep', 'nmap', 'portsweep', 'satan', 'mscan', 'saint']:
        return 'PROBE'
    elif name in ['ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy', 'warezclient', 'warezmaster', 'xlock', 'xsnoop', 'sendmail', 'snmpgetattack', 'snmpguess']:
        return 'R2L'
    elif name in ['buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'xterm', 'ps']:
        return 'U2R'
    else:
        return 'normal'

df['Attack_Class'] = df['attack'].apply(map_attack_type)

# ==== Load models ====
binary_model = joblib.load("models/binary_model.pkl")
multi_model = joblib.load("models/multiclass_model.pkl")

X = df.drop(columns=["attack", "last_flag", "Binary_Label", "Attack_Class"])

# ==== Binary Classification Evaluation ====
y_true_binary = df["Binary_Label"]
y_pred_binary = binary_model.predict(X)

print("\n🔒 Binary Classification (Normal vs Attack):")
print("Accuracy:", round(accuracy_score(y_true_binary, y_pred_binary) * 100, 2), "%")
print(classification_report(y_true_binary, y_pred_binary, target_names=["Normal", "Attack"]))

# ==== Multiclass Classification Evaluation ====
y_true_multi = df["Attack_Class"]
y_pred_multi = multi_model.predict(X)

print("\n🧠 Multiclass Attack Classification (DOS / PROBE / R2L / U2R / normal):")
print("Accuracy:", round(accuracy_score(y_true_multi, y_pred_multi) * 100, 2), "%")
print(classification_report(y_true_multi, y_pred_multi))

# Binary metrics
binary_scores = {
    "accuracy": round(accuracy_score(y_true_binary, y_pred_binary) * 100, 2),
    "precision": round(precision_score(y_true_binary, y_pred_binary, zero_division=0) * 100, 2),
    "recall": round(recall_score(y_true_binary, y_pred_binary, zero_division=0) * 100, 2),
    "f1_score": round(f1_score(y_true_binary, y_pred_binary, zero_division=0) * 100, 2)
}

# Multiclass metrics (macro-average)
multi_scores = {
    "accuracy": round(accuracy_score(y_true_multi, y_pred_multi) * 100, 2),
    "precision": round(precision_score(y_true_multi, y_pred_multi, average='macro', zero_division=0) * 100, 2),
    "recall": round(recall_score(y_true_multi, y_pred_multi, average='macro', zero_division=0) * 100, 2),
    "f1_score": round(f1_score(y_true_multi, y_pred_multi, average='macro', zero_division=0) * 100, 2)
}

# Save to JSON
output = {
    "binary": binary_scores,
    "multiclass": multi_scores
}

os.makedirs("data", exist_ok=True)  # Ensure 'data' folder exists
with open("data/evaluation_scores.json", "w") as f:
    json.dump(output, f, indent=4)

print("\n✅ Model performance saved to data/evaluation_scores.json")

