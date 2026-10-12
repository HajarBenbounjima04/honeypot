#!/usr/bin/env python3
import pandas as pd
import os
from datetime import datetime
from elasticsearch import Elasticsearch, helpers

# Load your zeroday dataset
ZERO_DAY_CSV = "data/dionaea/raw/zeroday_raw.csv"

df = pd.read_csv(ZERO_DAY_CSV)

# Load zero-day hashes (if found)
zeroday_hashes = []
zeroday_file = "data/dionaea/processed/zeroday_hashes.txt"
if os.path.exists(zeroday_file):
    with open(zeroday_file, 'r') as f:
        zeroday_hashes = [line.strip() for line in f]

# Prepare documents
docs = []
for _, row in df.iterrows():
    is_zeroday = row['sha256_hash'] in zeroday_hashes if zeroday_hashes else False
    
    doc = {
        'sha256_hash': row['sha256_hash'],
        'md5_hash': row.get('md5_hash', ''),
        'sha1_hash': row.get('sha1_hash', ''),
        'file_name': row.get('file_name', ''),
        'file_type': row.get('file_type', ''),
        'source_ip': row.get('source_ip', ''),
        'timestamp': row.get('timestamp', datetime.now().isoformat()),
        'is_zero_day_candidate': is_zeroday,
        'status': 'ZERO_DAY_CANDIDATE' if is_zeroday else 'KNOWN_MALWARE',
        'honeypot': row.get('honeypot', ''),
        'signature': row.get('signature', '')
    }
    docs.append(doc)

# Push to Elasticsearch
es = Elasticsearch("http://localhost:9200")

# Delete old index
if es.indices.exists(index="dionaea-zero-day"):
    es.indices.delete(index="dionaea-zero-day")
    print("[*] Deleted old zero-day index")

# Create new index
es.indices.create(index="dionaea-zero-day", ignore=400)

# Bulk push
actions = []
for doc in docs:
    actions.append({"_index": "dionaea-zero-day", "_source": doc})

if actions:
    success, _ = helpers.bulk(es, actions, raise_on_error=False)
    print(f"[✓] Pushed {success} documents to dionaea-zero-day")
    
    zero_day_count = sum(1 for d in docs if d['is_zero_day_candidate'])
    print(f"[✓] Zero-day candidates in index: {zero_day_count}")
