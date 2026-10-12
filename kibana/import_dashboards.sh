#!/bin/bash

KIBANA="http://kibana:5601"

echo "[*] Waiting for Kibana..."

until curl -s $KIBANA/api/status | grep -q "available"; do
  sleep 5
done

echo "[*] Importing dashboards..."

for file in /dashboards/*.ndjson; do
  echo "  -> Importing $file"

  curl -X POST "$KIBANA/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form file=@$file
done

echo "[✔] Dashboards imported successfully"