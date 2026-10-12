import os
import joblib
import pandas as pd
import numpy as np

# PATHS
FEATURES_CSV = "data/dionaea/processed/dionaea_features.csv"
OUTPUT_CSV = "data/dionaea/predictions/dionaea_predictions.csv"

MODEL_PATH = "models/dionaea/dionaea_model.pkl"
SCALER_PATH = "models/dionaea/dionaea_scaler.pkl"
FEAT_COLS_PATH = "models/dionaea/feature_columns.pkl"
THRESHOLD_PATH = "models/dionaea/anomaly_threshold.txt"

os.makedirs("data/dionaea/predictions", exist_ok=True)


def load_model_artifacts():
    """Load model, scaler, feature columns, and threshold"""
    print("[*] Loading model artifacts...")
    
    if not os.path.exists(MODEL_PATH):
        raise FileNotFoundError(f"Model not found at {MODEL_PATH}. Run model.py first.")
    if not os.path.exists(SCALER_PATH):
        raise FileNotFoundError(f"Scaler not found at {SCALER_PATH}. Run model.py first.")
    if not os.path.exists(FEAT_COLS_PATH):
        raise FileNotFoundError(f"Feature columns not found at {FEAT_COLS_PATH}. Run features.py first.")
    
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    feat_cols = joblib.load(FEAT_COLS_PATH)
    
    # Load threshold (from model training)
    if os.path.exists(THRESHOLD_PATH):
        with open(THRESHOLD_PATH, 'r') as f:
            threshold = float(f.read().strip())
        print(f"[i] Using saved threshold: {threshold:.4f}")
    else:
        # Fallback to percentile if threshold file missing
        threshold = None
        print("[w] No threshold file found, will use dynamic percentile")
    
    return model, scaler, feat_cols, threshold


def predict():
    """Run predictions on features data"""
    
    # Load artifacts
    model, scaler, feat_cols, saved_threshold = load_model_artifacts()
    
    # Load features
    print(f"[*] Loading features from: {FEATURES_CSV}")
    if not os.path.exists(FEATURES_CSV):
        raise FileNotFoundError(f"Features file not found at {FEATURES_CSV}. Run features.py first.")
    
    df = pd.read_csv(FEATURES_CSV)
    print(f"[i] Loaded {len(df)} IP records")
    
    # Check for required columns
    missing_cols = [col for col in feat_cols if col not in df.columns]
    if missing_cols:
        raise ValueError(f"Missing feature columns in data: {missing_cols}")
    
    # Prepare features
    X = df[feat_cols].fillna(0)
    
    # Scale features
    print("[*] Scaling features...")
    X_scaled = scaler.transform(X)
    
    # Predict
    print("[*] Running predictions...")
    
    # Get anomaly scores (higher = more suspicious)
    anomaly_scores = -model.score_samples(X_scaled)
    df["anomaly_score"] = anomaly_scores
    
    # Predict labels (-1 = anomaly/malicious, 1 = normal)
    predictions = model.predict(X_scaled)
    df["is_malicious_prediction"] = (predictions == -1).astype(int)
    
    # Determine threshold
    if saved_threshold is not None:
        THRESHOLD = saved_threshold
    else:
        # Dynamic threshold: 90th percentile of scores
        THRESHOLD = df["anomaly_score"].quantile(0.90)
        print(f"[i] Using dynamic threshold (90th percentile): {THRESHOLD:.4f}")
    
    # Define risk levels based on threshold and score
    def get_risk_level(score):
        if score >= THRESHOLD * 1.5:
            return "critical"
        elif score >= THRESHOLD * 1.2:
            return "high"
        elif score >= THRESHOLD:
            return "medium"
        elif score >= THRESHOLD * 0.5:
            return "low"
        else:
            return "info"
    
    def get_threat_label(score):
        if score >= THRESHOLD * 1.5:
            return "critical_anomaly"
        elif score >= THRESHOLD * 1.2:
            return "high_risk_behavior"
        elif score >= THRESHOLD:
            return "suspicious_activity"
        elif score >= THRESHOLD * 0.5:
            return "low_risk_behavior"
        else:
            return "normal_behavior"
    
    df["risk_level"] = df["anomaly_score"].apply(get_risk_level)
    df["threat_label"] = df["anomaly_score"].apply(get_threat_label)
    
    # Add confidence score (normalized between 0 and 1)
    max_score = df["anomaly_score"].max()
    min_score = df["anomaly_score"].min()
    if max_score > min_score:
        df["confidence"] = (df["anomaly_score"] - min_score) / (max_score - min_score)
    else:
        df["confidence"] = 0
    
    # Sort by most suspicious first
    df = df.sort_values("anomaly_score", ascending=False)
    
    # Save results
    df.to_csv(OUTPUT_CSV, index=False)
    
    # Summary
    print(f"\n[✔] Predictions saved → {OUTPUT_CSV}")
    print(f"\n{'='*50}")
    print("PREDICTION SUMMARY")
    print(f"{'='*50}")
    print(f"Total IPs analyzed: {len(df)}")
    print(f"Malicious predictions: {df['is_malicious_prediction'].sum()}")
    print(f"Threshold used: {THRESHOLD:.4f}")
    
    print("\nRisk Level Distribution:")
    risk_counts = df["risk_level"].value_counts()
    for level in ["critical", "high", "medium", "low", "info"]:
        count = risk_counts.get(level, 0)
        pct = (count / len(df)) * 100
        print(f"  {level:10s}: {count:4d} IPs ({pct:5.1f}%)")
    
    print("\nThreat Label Distribution:")
    print(df["threat_label"].value_counts())
    
    # Show top 10 most suspicious IPs
    print(f"\n{'='*50}")
    print("TOP 10 MOST SUSPICIOUS IPs")
    print(f"{'='*50}")
    top_ips = df.head(10)[["source_ip", "anomaly_score", "risk_level", "threat_label", "total_uploads"]]
    for idx, row in top_ips.iterrows():
        print(f"  {row['source_ip']:20s} | score={row['anomaly_score']:.4f} | "
              f"{row['risk_level']:8s} | {row['threat_label']:20s} | uploads={row['total_uploads']}")
    
    return df


def predict_single_ip(ip_address: str, features_df: pd.DataFrame = None):
    """Predict for a single IP address"""
    if features_df is None:
        features_df = pd.read_csv(FEATURES_CSV)
    
    model, scaler, feat_cols, threshold = load_model_artifacts()
    
    ip_data = features_df[features_df["source_ip"] == ip_address]
    if len(ip_data) == 0:
        return {"error": f"IP {ip_address} not found in features data"}
    
    X = ip_data[feat_cols].fillna(0)
    X_scaled = scaler.transform(X)
    score = -model.score_samples(X_scaled)[0]
    prediction = model.predict(X_scaled)[0]
    
    return {
        "ip": ip_address,
        "anomaly_score": float(score),
        "is_malicious": bool(prediction == -1),
        "risk_level": "critical" if score >= threshold * 1.5 else
                     "high" if score >= threshold * 1.2 else
                     "medium" if score >= threshold else
                     "low" if score >= threshold * 0.5 else "info",
        "threshold": float(threshold)
    }


if __name__ == "__main__":
    # Run full prediction
    results = predict()
    
    # Example: Predict for a specific IP (uncomment to test)
    # single_result = predict_single_ip("192.168.1.100")
    # print(f"\nSingle IP prediction: {single_result}")