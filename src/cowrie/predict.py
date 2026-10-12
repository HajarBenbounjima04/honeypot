"""
predict.py — Cowrie
Runs IsolationForest inference + labels
"""

import os
import joblib
import pandas as pd

# PATHS
FEATURES_CSV   = "data/cowrie/processed/cowrie_features.csv"
OUTPUT_CSV     = "data/cowrie/predictions/cowrie_predictions.csv"

MODEL_PATH     = "models/cowrie/cowrie_model.pkl"
SCALER_PATH    = "models/cowrie/cowrie_scaler.pkl"
FEAT_COLS_PATH = "models/cowrie/feature_columns.pkl"

os.makedirs("data/cowrie/predictions", exist_ok=True)

# LOAD MODEL
print("[*] Loading model...")

model = joblib.load(MODEL_PATH)
scaler = joblib.load(SCALER_PATH)
feat_cols = joblib.load(FEAT_COLS_PATH)

# LOAD DATA
print("[*] Loading features...")

df = pd.read_csv(FEATURES_CSV)

X = df.reindex(columns=feat_cols, fill_value=0).fillna(0)

# PREDICT
print("[*] Running predictions...")

X_scaled = scaler.transform(X)

# anomaly score (higher = more suspicious)
df["anomaly_score"] = -model.score_samples(X_scaled)

# dynamic threshold (IMPORTANT)
THRESHOLD = df["anomaly_score"].quantile(0.90)

# LABELS
def assign_label(score):
    if score >= 0.90:
        return "critical_anomaly"
    if score >= 0.75:
        return "novel_behavior"
    if score >= THRESHOLD:
        return "suspicious_activity"
    return "known_pattern"

def assign_tier(score):
    if score >= 0.90:
        return "critical"
    if score >= 0.75:
        return "high"
    if score >= THRESHOLD:
        return "medium"
    return "low"

df["final_label"] = df["anomaly_score"].apply(assign_label)
df["threat_tier"] = df["anomaly_score"].apply(assign_tier)

# SAVE
df.to_csv(OUTPUT_CSV, index=False)

# SUMMARY
print(f"\n[✔] Saved: {OUTPUT_CSV}")
print(df["threat_tier"].value_counts())
print(df["final_label"].value_counts())