
import pandas as pd
import os
from datetime import datetime
from elasticsearch import Elasticsearch, helpers

# Load zero-day raw data
ZERO_DAY_CSV = "data/dionaea/raw/zeroday_raw.csv"
ZERO_DAY_HASHES_FILE = "data/dionaea/processed/zeroday_hashes.txt"

# Load the zero-day hashes (from VT query)
zero_day_hashes = set()
if os.path.exists(ZERO_DAY_HASHES_FILE):
    with open(ZERO_DAY_HASHES_FILE, 'r') as f:
        zero_day_hashes = set(line.strip() for line in f)
    print(f"[*] Loaded {len(zero_day_hashes)} zero-day hashes from VT")
else:
    print("[!] No zero-day hashes file found")

# Load raw data
df = pd.read_csv(ZERO_DAY_CSV)
print(f"[*] Loading {len(df)} total records")

# Prepare documents
docs = []
for _, row in df.iterrows():
    sha256 = str(row.get('sha256_hash', ''))
    is_zero_day = sha256 in zero_day_hashes
    
    doc = {
        'sha256_hash': sha256,
        'md5_hash': str(row.get('md5_hash', '')),
        'file_name': str(row.get('file_name', '')),
        'file_type': str(row.get('file_type', '')),
        'source_ip': str(row.get('source_ip', '')),
        'timestamp': str(row.get('timestamp', datetime.now().isoformat())),
        'is_zero_day_candidate': is_zero_day,
        'status': 'ZERO_DAY_CANDIDATE' if is_zero_day else 'KNOWN_MALWARE',
        '@timestamp': datetime.now().isoformat()
    }
    docs.append(doc)

# Push to Elasticsearch
print("[*] Connecting to Elasticsearch...")
es = Elasticsearch("http://localhost:9200")

if not es.ping():
    print("[!] Elasticsearch not running!")
    exit(1)

# Delete old index
if es.indices.exists(index="dionaea-zero-day"):
    es.indices.delete(index="dionaea-zero-day")
    print("[*] Deleted old zero-day index")

# Bulk push
print("[*] Pushing documents...")
actions = [{ "_index": "dionaea-zero-day", "_source": doc } for doc in docs]
success, _ = helpers.bulk(es, actions, raise_on_error=False)
print(f"[✓] Pushed {success} documents to dionaea-zero-day")

zero_day_count = sum(1 for d in docs if d['is_zero_day_candidate'])
print(f"[✓] Zero-day candidates: {zero_day_count}")
print(f"[✓] Known malware: {success - zero_day_count}")
