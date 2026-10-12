"""
cowrie_model.py — Train IsolationForest on Cowrie data
"""
import os
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# PATHS
FEATURES_CSV = "data/cowrie/processed/cowrie_features.csv"
MODEL_PATH = "models/cowrie/cowrie_model.pkl"
SCALER_PATH = "models/cowrie/cowrie_scaler.pkl"
FEAT_COLS_PATH = "models/cowrie/feature_columns.pkl"

os.makedirs("models/cowrie", exist_ok=True)

# COWRIE FEATURES (from your features.py)
FEATURE_COLS = [
    "total_events",
    "unique_sessions",
    "failed_logins",
    "success_logins",
    "unique_usernames",
    "unique_passwords",
    "unique_dst_ports",
    "unique_protocols",
    "commands_executed",
    "files_downloaded",
    "c2_connections",
    "has_payload",
    "avg_session_duration",
    "total_bytes_sent",
    "total_bytes_received",
    "high_severity_events",
    "medium_severity_events",
    "unique_mitre_techniques",
    "unique_attack_types",
    "compromised_count",
    "unique_commands",
    "suspicious_command_count",
    "uses_downloader",
    "exec_chain_detected",
    "fail_rate",
    "success_rate",
    "user_reuse_ratio",
    "cmd_per_session",
    "bytes_ratio",
    "threat_score",
    "connection_rate",
    "burst_score",
]

print("[*] Loading Cowrie features...")
df = pd.read_csv(FEATURES_CSV)

# Check which features exist
available = [c for c in FEATURE_COLS if c in df.columns]
missing = [c for c in FEATURE_COLS if c not in df.columns]

if missing:
    print(f"[!] Missing columns (ignored): {missing[:5]}...")

X = df[available].fillna(0)
print(f"[i] Rows: {len(X)} | Features: {len(available)}")

# Scale
scaler = StandardScaler()
X_scaled = scaler.fit_transform(X)

# Train model
print("[*] Training IsolationForest on Cowrie data...")
model = IsolationForest(
    n_estimators=300,
    contamination='auto',  # Let model find anomalies
    random_state=42,
    n_jobs=-1
)
model.fit(X_scaled)

# Save artifacts
joblib.dump(model, MODEL_PATH)
joblib.dump(scaler, SCALER_PATH)
joblib.dump(available, FEAT_COLS_PATH)

print(f"\n[✔] Cowrie Model saved: {MODEL_PATH}")
print(f"[✔] Cowrie Scaler saved: {SCALER_PATH}")
print(f"[✔] Cowrie Features saved: {FEAT_COLS_PATH}")

# Analysis
anomaly_scores = -model.score_samples(X_scaled)
print(f"\n[i] Anomaly Score Range: {anomaly_scores.min():.4f} to {anomaly_scores.max():.4f}")
print(f"[i] Mean Score: {anomaly_scores.mean():.4f}")