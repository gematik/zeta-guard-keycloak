#!/bin/bash

# Registers the HSM token signing KeyProvider component in each realm and removes
# software signing keys (rsa-generated, ecdsa-generated).
#
# Skips entirely when HSM_TOKEN_SIGNING_ENABLED != "true".
#
# Required env vars (on keycloak-config-cli):
#   HSM_TOKEN_SIGNING_ENABLED  — "true" to run
#   HSM_TOKEN_SIGNING_ENDPOINT — gRPC address of hsm-sim / HSM proxy
#   HSM_TOKEN_SIGNING_KEY_ID   — key identifier in the HSM

if [ "${HSM_TOKEN_SIGNING_ENABLED}" != "true" ]; then
  echo "HSM token signing not enabled — skipping"
  exit 0
fi

echo "Configure HSM token signing (endpoint=${HSM_TOKEN_SIGNING_ENDPOINT}, keyId=${HSM_TOKEN_SIGNING_KEY_ID})"

REALMS=("zeta-guard" "master")
PRIORITY="${HSM_TOKEN_SIGNING_PRIORITY:-200}"

for REALM in "${REALMS[@]}"; do
  echo "── Realm: ${REALM} ──────────────────────────────────────────────"

  # ── Register HSM KeyProvider component ────────────────────────────────────
  ./kcadm.sh get components -r "$REALM" --fields "id,providerId" > /tmp/kc_components.json

  EXISTING=$(jq -r '.[] | select(.providerId == "zeta-hsm-token-signing") | .id' < /tmp/kc_components.json | head -1)

  # Use a JSON file — kcadm's -s flag doesn't handle config arrays correctly
  cat > /tmp/hsm-component.json <<EOF
{
  "name": "hsm-token-signing",
  "providerId": "zeta-hsm-token-signing",
  "providerType": "org.keycloak.keys.KeyProvider",
  "config": {
    "priority": ["${PRIORITY}"],
    "endpoint": ["${HSM_TOKEN_SIGNING_ENDPOINT}"],
    "keyId": ["${HSM_TOKEN_SIGNING_KEY_ID}"]
  }
}
EOF

  if [ -n "$EXISTING" ]; then
    echo "Updating existing HSM KeyProvider (${EXISTING})"
    ./kcadm.sh update "components/${EXISTING}" -r "$REALM" -f /tmp/hsm-component.json
  else
    echo "Creating HSM KeyProvider"
    ./kcadm.sh create components -r "$REALM" -f /tmp/hsm-component.json
  fi

  # ── Remove software signing keys (keep encryption keys) ──────────────────
  ./kcadm.sh get components -r "$REALM" --fields "id,providerId,config" > /tmp/kc_keys.json

  REMOVED=0
  for PROVIDER_ID in "rsa-generated" "ecdsa-generated"; do
    IDS=$(jq -r --arg pid "$PROVIDER_ID" \
      '.[] | select(.providerId == $pid) | select(.config.keyUse == null or (.config.keyUse | first) != "enc") | .id' \
      < /tmp/kc_keys.json)

    for ID in $IDS; do
      echo "Removing software signing key: providerId=${PROVIDER_ID}, id=${ID}"
      ./kcadm.sh delete "components/${ID}" -r "$REALM"
      REMOVED=$((REMOVED + 1))
    done
  done

  if [ $REMOVED -eq 0 ]; then
    echo "No software signing keys found in realm ${REALM}"
  else
    echo "Removed ${REMOVED} software signing key(s) from realm ${REALM}"
  fi
done

# Re-authenticate: deleting signing keys invalidates the current kcadm session
# token (it was signed with a key we just removed). Subsequent scripts need a
# fresh token signed with the new HSM key.
echo "Re-authenticating kcadm after key rotation"
./kcadm.sh config credentials --server "$KEYCLOAK_URL" --realm master \
  --user "$KEYCLOAK_USER" --password "$KEYCLOAK_PASSWORD"

echo "HSM token signing configured"
