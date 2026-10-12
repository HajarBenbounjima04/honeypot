#!/usr/bin/env python3
import pandas as pd
import ast
import json
from elasticsearch import Elasticsearch, helpers
from datetime import datetime
import os

ES_HOST = "http://localhost:9200"
INDEX_NAME = "dionaea-malware-intel"
CSV_PATH = "data/dionaea/processed/vt_results.csv"

def clean_threat_label(label):
    if pd.isna(label) or label == 'Unknown':
        return 'Unknown'
    
    label_str = str(label)
    
    # Handle dict format {'count': X, 'value': 'name'}
    if label_str.startswith('{'):
        try:
            # Try ast.literal_eval first
            d = ast.literal_eval(label_str)
            if isinstance(d, dict):
                return d.get('value', d.get('name', 'Unknown'))
        except:
            pass
        try:
            # Try json.loads
            d = json.loads(label_str.replace("'", '"'))
            if isinstance(d, dict):
                return d.get('value', d.get('name', 'Unknown'))
        except:
            pass
    
    return label_str

def push():
    if not os.path.exists(CSV_PATH):
        print(f"[!] File not found: {CSV_PATH}")
        return False
    
    df = pd.read_csv(CSV_PATH)
    print(f"[*] Loading {len(df)} VirusTotal results")
    
    # Clean the threat_label column
    df['threat_label'] = df['threat_label'].apply(clean_threat_label)
    
    es = Elasticsearch(ES_HOST)
    
    if es.indices.exists(index=INDEX_NAME):
        es.indices.delete(index=INDEX_NAME)
        print(f"[*] Deleted old {INDEX_NAME}")
    
    actions = []
    for _, row in df.iterrows():
        doc = {
            'sha256_hash': str(row['sha256_hash']),
            'detection_rate': float(row.get('detection_rate', 0)),
            'malicious_count': int(row.get('malicious_count', 0)),
            'threat_label': row['threat_label'],
            'is_malicious': bool(row.get('is_malicious', False)),
            '@timestamp': datetime.now().isoformat()
        }
        actions.append({"_index": INDEX_NAME, "_source": doc})
    
    success, _ = helpers.bulk(es, actions, raise_on_error=False)
    print(f"[✓] Pushed {success} docs to [{INDEX_NAME}]")
    
    families = set(doc['_source']['threat_label'] for doc in actions if doc['_source']['is_malicious'])
    print(f"[✓] Malware families: {list(families)}")
    return True

if __name__ == "__main__":
    push()
