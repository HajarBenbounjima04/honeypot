#!/usr/bin/env python3
import requests
import os
import pandas as pd
import time
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
VT_URL = "https://www.virustotal.com/api/v3/files/"

# Use YOUR zeroday dataset
ZERO_DAY_CSV = "data/dionaea/raw/zeroday_raw.csv"

# Check if file exists
if not os.path.exists(ZERO_DAY_CSV):
    print(f"[!] File not found: {ZERO_DAY_CSV}")
    print("    Please update the path to your zeroday dataset")
    exit(1)

# Load hashes from your zeroday dataset
df = pd.read_csv(ZERO_DAY_CSV)
hashes = df['sha256_hash'].dropna().unique()
hashes = [h for h in hashes if h != "" and len(str(h)) > 10]

print(f"[*] Loaded {len(hashes)} unique SHA256 hashes from zeroday dataset")
print(f"[*] Checking {min(20, len(hashes))} hashes for zero-days...\n")

zero_days = []
known_malware = []

for i, h in enumerate(hashes[:20]):
    print(f"[{i+1}/20] {h[:32]}...", end=" ")
    
    headers = {"x-apikey": API_KEY}
    try:
        r = requests.get(f"{VT_URL}{h}", headers=headers, timeout=30)
        
        if r.status_code == 404:
            zero_days.append(h)
            print("🔴 ZERO-DAY CANDIDATE! (Not in any database)")
            
        elif r.status_code == 200:
            data = r.json()
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            total = sum(stats.values())
            
            if malicious == 0:
                zero_days.append(h)
                print(f"🟠 POSSIBLE ZERO-DAY (0/{total} detections)")
            else:
                known_malware.append(h)
                print(f"✅ Known malware ({malicious}/{total} engines)")
        else:
            print(f"❌ Error {r.status_code}")
            
    except Exception as e:
        print(f"❌ Connection error: {e}")
    
    time.sleep(15)  # Rate limit (4 per minute)

print("\n" + "=" * 60)
print("ZERO-DAY DISCOVERY RESULTS")
print("=" * 60)
print(f"Total hashes checked: {len(hashes[:20])}")
print(f"🔴 ZERO-DAY CANDIDATES: {len(zero_days)}")
print(f"✅ Known malware: {len(known_malware)}")

if zero_days:
    print("\n🔴 ZERO-DAY CANDIDATE HASHES:")
    for h in zero_days:
        print(f"  {h}")
    
    # Save zero-day hashes to file
    with open("data/dionaea/processed/zeroday_hashes.txt", "w") as f:
        for h in zero_days:
            f.write(f"{h}\n")
    print(f"\n[✓] Saved to: data/dionaea/processed/zeroday_hashes.txt")
else:
    print("\n[✓] No zero-day candidates found. All malware is known!")
