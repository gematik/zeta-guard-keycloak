#!/usr/bin/env bash
# Generates a self-signed EC P-256 cert for local TLS testing (scenario 4).
# Output: tls.crt (PEM certificate) + tls.key (PKCS8 PEM private key)
# These files are gitignored — run this script once before starting the stack.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"

echo "Generating self-signed EC P-256 cert in ${DIR}/"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${DIR}/tls.key"
openssl req -x509 -key "${DIR}/tls.key" -out "${DIR}/tls.crt" \
  -days 3650 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

echo "Done: tls.crt + tls.key"
