import os
import pandas as pd
import joblib

RAW_CSV = "data/dionaea/raw/dionaea_raw.csv"
OUT_CSV = "data/dionaea/processed/dionaea_features.csv"
FEATURES_LIST_PATH = "models/dionaea/feature_columns.pkl"

os.makedirs("data/dionaea/processed", exist_ok=True)
os.makedirs("models/dionaea", exist_ok=True)


def build_features(df: pd.DataFrame) -> pd.DataFrame:
    # ── Clean ──────────────────────────────────────────────────────────────────
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    df["source_ip"] = df["source_ip"].fillna("0.0.0.0")
    df["signature"] = df["signature"].fillna("unknown")
    df["file_type"] = df["file_type"].fillna("unknown")
    df["mime_type"] = df["mime_type"].fillna("unknown")
    df["protocol"] = df["protocol"].fillna("unknown")
    df["malware_reporter"] = df["malware_reporter"].fillna("unknown")
    df["vtpercent"] = pd.to_numeric(df["vtpercent"], errors="coerce").fillna(0)
    df["has_sha256"] = df["sha256_hash"].notna().astype(int)
    df["has_signature"] = (df["signature"] != "unknown").astype(int)

    # ── Get list of actual file types per IP ──────────────────────────────────
    # Collect all file types uploaded by each IP
    file_types_list = df.groupby("source_ip")["file_type"].apply(
        lambda x: [ft for ft in x.astype(str).tolist() if ft != "unknown" and ft != "nan"]
    ).reset_index(name="file_types_uploaded")
    
    # Get top 5 file types per IP with counts
    file_type_counts = df.groupby(["source_ip", "file_type"]).size().reset_index(name="count")
    file_type_counts = file_type_counts[file_type_counts["file_type"] != "unknown"]
    
    # Create summary string: "exe(5), jar(3), rar(2)"
    def get_top_file_types(ip):
        ip_data = file_type_counts[file_type_counts["source_ip"] == ip]
        if len(ip_data) == 0:
            return "none"
        top5 = ip_data.nlargest(5, "count")
        return ", ".join([f"{row['file_type']}({row['count']})" for _, row in top5.iterrows()])
    
    # ── Base aggregation per source_ip ─────────────────────────────────────────
    features = df.groupby("source_ip").agg(
        total_uploads=("file_type", "count"),
        unique_file_types=("file_type", "nunique"),
        unique_mime_types=("mime_type", "nunique"),
        unique_protocols=("protocol", "nunique"),
        unique_signatures=("signature", "nunique"),
        unique_reporters=("malware_reporter", "nunique"),
        avg_vtpercent=("vtpercent", "mean"),
        max_vtpercent=("vtpercent", "max"),
        known_malware=("has_signature", "sum"),
        files_with_hash=("has_sha256", "sum"),
        exe_uploads=("file_type", lambda x: (x == "exe").sum()),
        jar_uploads=("file_type", lambda x: (x == "jar").sum()),
        rar_uploads=("file_type", lambda x: (x == "rar").sum()),
        pdf_uploads=("file_type", lambda x: (x == "pdf").sum()),
        doc_uploads=("file_type", lambda x: ((x == "doc") | (x == "docx")).sum()),
        zip_uploads=("file_type", lambda x: (x == "zip").sum()),
    ).reset_index()
    
    # Add the actual file type names
    features["file_types_uploaded"] = features["source_ip"].apply(
        lambda ip: file_types_list[file_types_list["source_ip"] == ip]["file_types_uploaded"].values[0] 
        if len(file_types_list[file_types_list["source_ip"] == ip]) > 0 else []
    )
    
    features["top_file_types"] = features["source_ip"].apply(get_top_file_types)
    
    # Count how many different file types (unique)
    features["unique_file_type_count"] = features["file_types_uploaded"].apply(
        lambda x: len(set(x)) if isinstance(x, list) else 0
    )

    # ── Derived features ───────────────────────────────────────────────────────
    total = features["total_uploads"]
    features["malware_ratio"] = features["known_malware"] / (total + 1)
    features["hash_ratio"] = features["files_with_hash"] / (total + 1)
    features["high_risk_uploads"] = (features["max_vtpercent"] > 70).astype(int)
    features["suspicious_activity"] = (
        features["malware_ratio"] + (features["avg_vtpercent"] / 100)
    )
    features["exe_ratio"] = features["exe_uploads"] / (total + 1)

    # ── Time-based: upload rate + burst ───────────────────────────────────────
    def time_features(group):
        ts = group["timestamp"].dropna().sort_values()
        if len(ts) < 2:
            return pd.Series({"upload_rate": 0.0, "burst_score": 0.0})
        duration_minutes = max((ts.iloc[-1] - ts.iloc[0]).total_seconds() / 60, 1)
        rate = len(ts) / duration_minutes
        gaps = ts.diff().dt.total_seconds().dropna()
        burst = 1 / (gaps.std() + 1) if len(gaps) > 0 else 0
        return pd.Series({"upload_rate": round(rate, 4), "burst_score": round(burst, 4)})

    time_feats = df.groupby("source_ip").apply(time_features).reset_index()
    features = features.merge(time_feats, on="source_ip", how="left")
    features[["upload_rate", "burst_score"]] = (
        features[["upload_rate", "burst_score"]].fillna(0)
    )

    return features


def main():
    print("[*] Loading raw Dionaea data from:", RAW_CSV)
    df = pd.read_csv(RAW_CSV)
    print(f"    {len(df):,} raw rows | {df['source_ip'].nunique():,} unique IPs")

    features = build_features(df)
    
    # Save features
    features.to_csv(OUT_CSV, index=False)
    
    # Save feature columns list for predict.py
    feature_columns = [col for col in features.columns if col != 'source_ip']
    joblib.dump(feature_columns, FEATURES_LIST_PATH)
    
    print(f"[✔] Dionaea features saved → {OUT_CSV}")
    print(f"    {len(features):,} IP rows | {len(features.columns)} feature columns")
    print(f"[✔] Feature columns saved → {FEATURES_LIST_PATH}")
    print(f"\n[i] New columns added:")
    print(f"    - file_types_uploaded: List of all file types per IP")
    print(f"    - top_file_types: Top 5 file types with counts (ex: exe(5), jar(3))")
    print(f"    - unique_file_type_count: Number of unique file types")
    print(f"    - pdf_uploads, doc_uploads, zip_uploads: Additional file type counts")
    print(f"\n    Columns: {list(features.columns)}")


if __name__ == "__main__":
    main()