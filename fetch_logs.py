import requests
import pandas as pd
import os

ES_HOST = "http://localhost:9200"

def fetch_and_save():
    # Cowrie
    print("Fetching Cowrie...")
    r = requests.post(f"{ES_HOST}/cowrie-logs/_search", 
                     json={"query": {"term": {"honeypot": "cowrie"}}, "size": 10000})
    if r.status_code == 200:
        logs = [h['_source'] for h in r.json()['hits']['hits']]
        if logs:
            df = pd.DataFrame(logs)
            os.makedirs("data/cowrie/raw", exist_ok=True)
            df.to_csv("data/cowrie/raw/cowrie_raw.csv", index=False)
            print(f"  Saved {len(df)} Cowrie logs")
        else:
            print("  No Cowrie logs")
    else:
        print(f"  Cowrie error: {r.status_code}")
    
    # Dionaea
    print("Fetching Dionaea...")
    r = requests.post(f"{ES_HOST}/dionaea-logs/_search",
                     json={"query": {"term": {"honeypot": "dionaea"}}, "size": 10000})
    if r.status_code == 200:
        logs = [h['_source'] for h in r.json()['hits']['hits']]
        if logs:
            df = pd.DataFrame(logs)
            os.makedirs("data/dionaea/raw", exist_ok=True)
            df.to_csv("data/dionaea/raw/dionaea_raw.csv", index=False)
            print(f"  Saved {len(df)} Dionaea logs")
        else:
            print("  No Dionaea logs")
    else:
        print(f"  Dionaea error: {r.status_code}")

if __name__ == "__main__":
    fetch_and_save()
