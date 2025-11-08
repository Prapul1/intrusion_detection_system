import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
import os

print("🚀 Loading KDD dataset...")

# File paths
train_path = "data/KDDTrain+.txt"
test_path = "data/KDDTest+.txt"

# Column names (41 features + 1 label)
column_names = [
    'duration','protocol_type','service','flag','src_bytes','dst_bytes','land',
    'wrong_fragment','urgent','hot','num_failed_logins','logged_in','num_compromised',
    'root_shell','su_attempted','num_root','num_file_creations','num_shells',
    'num_access_files','num_outbound_cmds','is_host_login','is_guest_login','count',
    'srv_count','serror_rate','srv_serror_rate','rerror_rate','srv_rerror_rate',
    'same_srv_rate','diff_srv_rate','srv_diff_host_rate','dst_host_count',
    'dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate',
    'dst_host_same_src_port_rate','dst_host_srv_diff_host_rate','dst_host_serror_rate',
    'dst_host_srv_serror_rate','dst_host_rerror_rate','dst_host_srv_rerror_rate',
    'label'
]

# Load data
train_df = pd.read_csv(train_path, names=column_names, sep=",", engine='python')
test_df = pd.read_csv(test_path, names=column_names, sep=",", engine='python')

print(f"✅ Train shape: {train_df.shape}, Test shape: {test_df.shape}")

# Combine both for consistent encoding
data = pd.concat([train_df, test_df], axis=0)

# ✅ Encode *all* string/categorical columns automatically
for col in data.columns:
    if data[col].dtype == 'object':
        le = LabelEncoder()
        data[col] = le.fit_transform(data[col])

# ✅ Split features and labels
X = data.drop('label', axis=1)
y = data['label']

# ✅ Normalize numeric data
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# ✅ Split into train/test again for fairness
X_train, X_test, y_train, y_test = train_test_split(
    X_scaled, y, test_size=0.2, random_state=42, stratify=y
)

# ✅ Save preprocessed data
os.makedirs("data", exist_ok=True)
pd.DataFrame(X_train).to_csv("data/X_train.csv", index=False)
pd.DataFrame(X_test).to_csv("data/X_test.csv", index=False)
pd.DataFrame(y_train).to_csv("data/y_train.csv", index=False)
pd.DataFrame(y_test).to_csv("data/y_test.csv", index=False)

print("🎯 Preprocessing complete. Processed files saved in 'data/' folder.")
