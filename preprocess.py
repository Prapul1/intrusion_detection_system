# preprocess.py
import os
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, StandardScaler
import joblib

# ---------------- CONFIG ----------------
DATA_DIR = "data"
TRAIN_FILE = os.path.join(DATA_DIR, "KDDTrain+.txt")
TEST_FILE = os.path.join(DATA_DIR, "KDDTest+.txt")
OUTPUT_DIR = "processed"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Column names for NSL-KDD dataset (43 columns total)
cols = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
    "logged_in", "num_compromised", "root_shell", "su_attempted",
    "num_root", "num_file_creations", "num_shells", "num_access_files",
    "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
    "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate", "label", "difficulty"
]

# ---------------- HELPERS ----------------
def load_nsl_kdd(path):
    """Loads NSL-KDD dataset with automatic comma/space detection."""
    try:
        df = pd.read_csv(path, names=cols)
    except Exception:
        df = pd.read_csv(path, names=cols, delim_whitespace=True)
    return df


def map_label(lbl):
    """Map detailed attack labels to broad categories."""
    lbl = str(lbl).strip().lower()

    if lbl == "normal":
        return "normal"
    elif lbl in ["neptune", "smurf", "back", "teardrop", "pod", "land", "apache2", "mailbomb", "processtable", "udpstorm"]:
        return "dos"
    elif lbl in ["satan", "ipsweep", "nmap", "portsweep", "mscan", "saint"]:
        return "probe"
    elif lbl in ["warezclient", "warezmaster", "ftp_write", "imap", "phf", "spy", "multihop", "guess_passwd", "snmpguess", "snmpgetattack", "httptunnel"]:
        return "r2l"
    elif lbl in ["buffer_overflow", "rootkit", "loadmodule", "perl", "xterm", "ps", "sqlattack", "xlock", "xsnoop"]:
        return "u2r"
    else:
        return "unknown"


# ---------------- MAIN ----------------
def preprocess_and_save(train_path, test_path):
    print("Loading train...")
    df_train = load_nsl_kdd(train_path)
    print("Loading test...")
    df_test = load_nsl_kdd(test_path)

    print("Initial sizes:", df_train.shape, df_test.shape)
    print("Columns in dataset:", df_train.columns.tolist())
    print(df_train.head())

    # Drop 'difficulty' column if it exists
    if "difficulty" in df_train.columns:
        df_train = df_train.drop(columns=["difficulty"])
    if "difficulty" in df_test.columns:
        df_test = df_test.drop(columns=["difficulty"])

    # Map labels to categories
    df_train["label_cat"] = df_train["label"].apply(map_label)
    df_test["label_cat"] = df_test["label"].apply(map_label)

    print("Train label distribution:")
    print(df_train["label_cat"].value_counts())
    print("Test label distribution:")
    print(df_test["label_cat"].value_counts())

    # Drop the original text label column
    df_train = df_train.drop(columns=["label"])
    df_test = df_test.drop(columns=["label"])

    # Encode categorical columns
    cat_cols = ["protocol_type", "service", "flag"]
    encoders = {}

    for c in cat_cols:
        le = LabelEncoder()
        df_train[c] = le.fit_transform(df_train[c].astype(str))

        # Handle unseen test labels
        df_test[c] = df_test[c].astype(str).apply(lambda x: x if x in le.classes_ else "unknown")
        le_classes = np.append(le.classes_, "unknown")
        le.classes_ = le_classes
        df_test[c] = le.transform(df_test[c])

        encoders[c] = le
        joblib.dump(le, os.path.join(OUTPUT_DIR, f"le_{c}.joblib"))

    # Split features and target
    X_train = df_train.drop(columns=["label_cat"])
    y_train = df_train["label_cat"]
    X_test = df_test.drop(columns=["label_cat"])
    y_test = df_test["label_cat"]

    # Scale numeric columns
    scaler = StandardScaler()
    numeric_cols = X_train.select_dtypes(include=[np.number]).columns.tolist()
    print("Numeric columns count:", len(numeric_cols))

    X_train[numeric_cols] = scaler.fit_transform(X_train[numeric_cols])
    X_test[numeric_cols] = scaler.transform(X_test[numeric_cols])
    joblib.dump(scaler, os.path.join(OUTPUT_DIR, "scaler.joblib"))

    # Ensure clean index before saving
    X_train = X_train.reset_index(drop=True)
    y_train = y_train.reset_index(drop=True)
    X_test = X_test.reset_index(drop=True)
    y_test = y_test.reset_index(drop=True)

    # Save processed CSVs
    train_proc = pd.concat([X_train, y_train], axis=1)
    test_proc = pd.concat([X_test, y_test], axis=1)

    train_proc.to_csv(os.path.join(OUTPUT_DIR, "train_processed.csv"), index=False)
    test_proc.to_csv(os.path.join(OUTPUT_DIR, "test_processed.csv"), index=False)

    print("✅ Saved processed files to", OUTPUT_DIR)
    print("X_train shape:", X_train.shape)
    print("Classes:", sorted(y_train.unique()))

    return X_train, X_test, y_train, y_test


if __name__ == "__main__":
    X_train, X_test, y_train, y_test = preprocess_and_save(TRAIN_FILE, TEST_FILE)
    print("Preprocessing done successfully.")
