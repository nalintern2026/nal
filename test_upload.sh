#!/bin/bash
# Test script to upload a CSV file and check results.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
API_BASE="${API_BASE:-http://localhost:8000/api}"
FILE="${1:-$SCRIPT_DIR/training_pipeline/data/processed/cic_ids/flows/monday/monday__00000_20170703172558.csv}"

if [ ! -f "$FILE" ]; then
  echo "File not found: $FILE"
  echo "Usage: ./test_upload.sh /path/to/file.csv"
  exit 1
fi

echo "Testing file upload with: $FILE"
curl -sS -X POST -F "file=@$FILE" "$API_BASE/upload" | python3 -m json.tool

echo ""
echo "Checking dashboard stats after upload..."
sleep 1
curl -sS "$API_BASE/dashboard/stats" | python3 -m json.tool
