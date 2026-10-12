
import os
import time
import requests
import pandas as pd
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Load hashes from raw data
df = pd.read_csv('data/dionaea/raw/dionaea_raw.csv')
hashes = df['sha256_hash'].dropna().unique()
hashes = [h for h in hashes if h != "" and len(str(h)) > 10][:10]  # First 10 for demo

print("=" * 60)
print("REAL-TIME VIRUSTOTAL QUERY")
print("=" * 60)
print(f"Checking {len(hashes)} file hashes against VirusTotal...\n")

for i, h in enumerate(hashes, 1):
    print(f"[{i}/{len(hashes)}] {h[:32]}...", end=" ")
    
    headers = {"x-apikey": API_KEY}
    try:
        r = requests.get(f"{VT_URL}{h}", headers=headers, timeout=30)
        
        if r.status_code == 404:
            print("❌ NOT IN DATABASE → Zero-day candidate!")
        elif r.status_code == 200:
            data = r.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            # Get malware name
            popular = data.get('data', {}).get('attributes', {}).get('popular_threat_classification', {})
            name = popular.get('popular_threat_name', ['Unknown'])[0] if popular else 'Unknown'
            
            if malicious > 0:
                print(f"✅ KNOWN MALWARE - {name} ({malicious}/{total} engines)")
            else:
                print(f"⚠️ CLEAN (0/{total} detections)")
        else:
            print(f"❌ Error {r.status_code}")
    except Exception as e:
        print(f"❌ Error")
    
    time.sleep(2)  # Faster for demo

print("\n" + "=" * 60)
print("✅ Query complete! Results saved to Elasticsearch")

