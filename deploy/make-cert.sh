#!/usr/bin/env bash
# Self-signed certificate for the lab. Browsers will warn; that is expected and worth
# a sentence in the report, because a real deployment uses a certificate from a CA.
set -euo pipefail

HOST="${1:-mfa-poc.lab}"
IP="${2:-127.0.0.1}"
OUT="${3:-/etc/ssl/mfapoc}"

sudo mkdir -p "$OUT"
sudo openssl req -x509 -nodes -newkey rsa:4096 -days 365 \
    -keyout "$OUT/mfapoc.key" \
    -out "$OUT/mfapoc.crt" \
    -subj "/CN=$HOST" \
    -addext "subjectAltName=DNS:$HOST,IP:$IP"
sudo chmod 600 "$OUT/mfapoc.key"
echo "certificate written to $OUT"
