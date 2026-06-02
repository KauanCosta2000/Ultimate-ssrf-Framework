#!/bin/bash

set -e

TARGET="${TARGET:-example.com}"
CALLBACK="${CALLBACK:-your-callback.oastify.com}"
PROXY="${PROXY:-http://127.0.0.1:8080}"
OUTPUT="${OUTPUT:-reports-proxy}"

echo "[*] Starting proxied SSRF scan"
echo "[*] Target: $TARGET"
echo "[*] Callback: $CALLBACK"
echo "[*] Proxy: $PROXY"
echo "[*] Output: $OUTPUT"
echo

python ssrf_arsenal.py \
  --target "$TARGET" \
  --callback "$CALLBACK" \
  --proxy "$PROXY" \
  --output "$OUTPUT" \
  --no-ai \
  --export-json-api
