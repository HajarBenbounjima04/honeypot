"""
push_to_elastic.py — Dionaea
Pushes Dionaea predictions to Elasticsearch
"""

import os
import math
import pandas as pd
from datetime import datetime, timezone
from elasticsearch import Elasticsearch, helpers

ES_HOST = os.getenv("ES_HOST", "http://localhost:9200")
INDEX   = os.getenv("DIONAEA_PRED_INDEX", "dionaea-predictions")

# Try multiple possible file paths
POSSIBLE_CSV_PATHS = [
    "data/dionaea/predictions/dionaea_predictions.csv",  # Main prediction output
    "data/dionaea/predictions/train_predictions.csv",    # Legacy name
    "data/dionaea/predictions/anomaly_scores.csv",       # Scores only
]

es = Elasticsearch(ES_HOST)

def clean(val):
    """Convert NaN/inf to None for Elasticsearch"""
    if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
        return None
    if pd.isna(val):
        return None
    return val

def find_csv():
    """Find which CSV file exists"""
    for path in POSSIBLE_CSV_PATHS:
        if os.path.exists(path):
            return path
    return None

def push():
    # Find CSV file
    csv_path = find_csv()
    if not csv_path:
        print(f"[!] No prediction CSV found. Tried:")
        for path in POSSIBLE_CSV_PATHS:
            print(f"     - {path}")
        return
    
    print(f"[*] Loading predictions from: {csv_path}")
    df = pd.read_csv(csv_path)
    print(f"    {len(df):,} rows")
    
    # Handle different column names
    if 'is_anomaly' in df.columns:
        anomaly_col = 'is_anomaly'
        anomaly_count = df['is_anomaly'].sum()
    elif 'is_malicious' in df.columns:
        anomaly_col = 'is_malicious'
        anomaly_count = df['is_malicious'].sum()
    else:
        anomaly_col = None
        anomaly_count = 0
        print(f"[!] No anomaly column found. Available: {list(df.columns[:5])}...")
    
    if anomaly_col:
        print(f"    Anomalies detected: {anomaly_count}")
    
    # Prepare documents for Elasticsearch
    actions = []
    for _, row in df.iterrows():
        # Convert row to dict and clean
        doc = {c: clean(row[c]) for c in df.columns}
        
        # Add metadata
        doc["honeypot"] = "dionaea"
        doc["@timestamp"] = datetime.now(timezone.utc).isoformat()
        
        # Add source IP field (normalize for Kibana)
        if 'source_ip' in doc:
            doc['source.ip'] = doc['source_ip']
        elif 'src_ip' in doc:
            doc['source.ip'] = doc['src_ip']
        
        actions.append({"_index": INDEX, "_source": doc})
    
    # Bulk push to Elasticsearch
    print(f"[*] Pushing {len(actions)} documents to Elasticsearch...")
    
    try:
        success, failed = helpers.bulk(
            es, actions, 
            raise_on_error=False, 
            stats_only=False,
            chunk_size=500
        )
        
        errors = [r for r in failed] if isinstance(failed, list) else []
        
        print(f"\n[✔] Successfully pushed {success} docs to [{INDEX}]")
        if errors:
            print(f"[!] {len(errors)} errors")
            # Show first error details
            first_error = errors[0]
            if isinstance(first_error, dict):
                print(f"    First error: {first_error.get('error', {}).get('reason', 'Unknown')}")
    except Exception as e:
        print(f"[✗] Failed to push to Elasticsearch: {e}")

if __name__ == "__main__":
    # Test connection first
    try:
        if es.ping():
            print("[✓] Connected to Elasticsearch")
            push()
        else:
            print("[✗] Cannot connect to Elasticsearch. Is it running?")
            print(f"    Check: {ES_HOST}")
    except Exception as e:
        print(f"[✗] Connection error: {e}")