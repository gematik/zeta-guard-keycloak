#!/usr/bin/env bash
# Generates the throwaway mTLS material for overlays/compose.sekidp-mtls.yaml (scenario: SekIDP flow with mTLS).
# Output: sekidp-client-testonly.p12, sekidp-server-cert-testonly.pem
# These files are gitignored — run this script once before starting the stack with that overlay.

set -euo pipefail

DIR="$(cd "$(dirname "$0")" && pwd)"
PASSWORD="testpass123"

# Intermediate private keys never touch the repo — a failed step must not leave stageable key files behind.
TMP="$(mktemp -d)"
trap 'rm -rf "${TMP}"' EXIT

echo "Generating SekIDP mTLS test material in ${DIR}/"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${TMP}/client.key"
openssl req -x509 -key "${TMP}/client.key" -out "${TMP}/client.crt" -days 30 -subj "/CN=sekidp-mtls-test-client"
openssl pkcs12 -export -inkey "${TMP}/client.key" -in "${TMP}/client.crt" -out "${DIR}/sekidp-client-testonly.p12" \
  -name sekidp-client -passout "pass:${PASSWORD}"

openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${TMP}/server.key"
openssl req -x509 -key "${TMP}/server.key" -out "${DIR}/sekidp-server-cert-testonly.pem" -days 365 -subj "/CN=host.docker.internal" \
  -addext "subjectAltName=DNS:host.docker.internal,DNS:localhost"

echo "Done: sekidp-client-testonly.p12, sekidp-server-cert-testonly.pem"
