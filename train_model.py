import os
import zipfile
import pandas as pd
import joblib
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.utils import resample

# === Setup ===
os.makedirs("models", exist_ok=True)
os.makedirs("data", exist_ok=True)

# === Unzip Dataset if needed ===
if not os.path.exists("data/dataset/Train.txt"):
    with zipfile.ZipFile("dataset.zip", 'r') as zip_ref:
        zip_ref.extractall("data")

# === Column names for dataset ===
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
"wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
"num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
"num_shells", "num_access_files", "num_outbound_cmds", "is_host_login",
"is_guest_login", "count", "srv_count", "serror_rate", "srv_serror_rate",
"rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
"dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
"dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
"dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
"attack", "last_flag"]

# === Load dataset ===
df = pd.read_csv("data/dataset/Train.txt", names=columns)

# === Binary attack labels ===
df["attack_binary"] = df["attack"].apply(lambda x: 0 if x == "normal" else 1)

# === Multiclass mapping ===
def classify_attack(x):
    if x in ["neptune", "smurf", "back", "pod", "teardrop", "land"]:
        return "DOS"
    elif x in ["satan", "ipsweep", "nmap", "portsweep"]:
        return "PROBE"
    elif x in ["ftp_write", "guess_passwd", "imap", "multihop", "phf", "spy", "warezclient", "warezmaster"]:
        return "R2L"
    elif x in ["buffer_overflow", "loadmodule", "perl", "rootkit"]:
        return "U2R"
    elif x == "normal":
        return "normal"
    else:
        return "unknown"

df["attack_multi"] = df["attack"].apply(classify_attack)

# === Filter out unknowns (optional) ===
df = df[df["attack_multi"] != "unknown"]

# === Encode categorical columns ===
for col in ["protocol_type", "service", "flag"]:
    df[col] = LabelEncoder().fit_transform(df[col])

# === Features and labels ===
X = df.drop(columns=["attack", "last_flag", "attack_binary", "attack_multi"])
# Filter unknowns before anything else
df = df[df["attack_multi"] != "unknown"]

# Now define labels (after filtering)
y_binary = df["attack_binary"]
y_multi = df["attack_multi"]


# === Train Binary Classifier (Normal vs Attack) ===
X_train_bin, X_test_bin, y_train_bin, y_test_bin = train_test_split(
    X, y_binary, test_size=0.2, stratify=y_binary, random_state=42
)

clf_binary = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
clf_binary.fit(X_train_bin, y_train_bin)
joblib.dump(clf_binary, "models/binary_model.pkl")
print("✅ Binary model trained and saved.")

# === Train Multiclass Classifier (DOS, PROBE, etc.) ===
X_train_multi, X_test_multi, y_train_multi, y_test_multi = train_test_split(
    X, y_multi, test_size=0.2, stratify=y_multi, random_state=42
)

clf_multi = RandomForestClassifier(n_estimators=100, class_weight="balanced", random_state=42)
clf_multi.fit(X_train_multi, y_train_multi)
joblib.dump(clf_multi, "models/multiclass_model.pkl")
print("✅ Multiclass model trained and saved.")
