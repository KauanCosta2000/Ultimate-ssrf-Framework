#!/bin/bash

set -e

TARGET="${TARGET:-example.com}"
CALLBACK="${CALLBACK:-your-callback.oastify.com}"
OUTPUT="${OUTPUT:-reports-basic}"

echo "[*] Starting basic SSRF scan"
echo "[*] Target: $TARGET"
echo "[*] Callback: $CALLBACK"
echo "[*] Output: $OUTPUT"
echo

python ssrf_arsenal.py \
  --target "$TARGET" \
  --callback "$CALLBACK" \
  --output "$OUTPUT" \
  --no-grpc \
  --no-websocket \
  --no-k8s \
  --no-serverless \
  --no-ai \
  --export-json-api
