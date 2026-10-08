#!/bin/bash

echo "🛠️ Setup ZETA mobile browser flow (zeta-mobile → Identity Provider Redirector → SekIDP)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping mobile browser flow (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

# Browser flow for mobile clients: an Identity Provider Redirector with default IdP zeta-sekidp-oidc.
# Mobile clients get this flow during DCR as a browserFlow override (ZetaGuardClientRegistrationPolicy),
# which enforces the SekIDP redirect server-side (no login screen).
#
# NOTE: the headless first-broker-login flow (zeta-mobile-first-login) is created in
# 13-create-sekidp-identity-provider.sh — it must exist before the IdP, which references it directly.
# This script runs AFTER the IdP so the redirector below can point at an existing default provider.

REALM="zeta-guard"
FLOW="zeta-mobile"
IDP="zeta-sekidp-oidc"

# 1) Create top-level browser flow (empty)
./kcadm.sh create authentication/flows -r "$REALM" \
  -s alias="$FLOW" \
  -s providerId=basic-flow \
  -s topLevel=true \
  -s builtIn=false \
  -s "description=ZETA mobile: enforced redirect to the SekIDP (no login screen)"

# 2) Add the Identity Provider Redirector as the only execution
./kcadm.sh create "authentication/flows/$FLOW/executions/execution" -r "$REALM" \
  -b '{"provider":"identity-provider-redirector"}'

# 3) Determine the execution id (the flow has exactly one execution → first "id"). No jq in the container.
EXEC_ID=$(./kcadm.sh get "authentication/flows/$FLOW/executions" -r "$REALM" \
  | grep '"id"' | head -1 | sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
echo "   execution id: $EXEC_ID"
if [ -z "$EXEC_ID" ]; then
  echo "❌ Could not determine the execution id for flow '$FLOW' — aborting."
  exit 1
fi

# 4) Set the redirector to REQUIRED
./kcadm.sh update "authentication/flows/$FLOW/executions" -r "$REALM" \
  -b "{\"id\":\"$EXEC_ID\",\"requirement\":\"REQUIRED\"}"

# 5) Configure the default IdP → automatic redirect to the SekIDP
./kcadm.sh create "authentication/executions/$EXEC_ID/config" -r "$REALM" \
  -b "{\"alias\":\"$FLOW-redirector\",\"config\":{\"defaultProvider\":\"$IDP\"}}"
