#!/bin/bash

echo "🛠️ Setup ZETA mobile browser flow (zeta-mobile → SekIDP Direct Redirector → SekIDP)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping mobile browser flow (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

# Browser flow for mobile clients: sekidp-direct-redirector, hardcoded to the zeta-sekidp-oidc alias.
# Mobile clients get this flow during DCR as a browserFlow override (ZetaGuardClientRegistrationPolicy),
# which enforces the SekIDP redirect.
# Runs AFTER script 13 so the zeta-sekidp-oidc alias the redirector below targets already exists.
#
# Uses our own sekidp-direct-redirector instead of Keycloak's stock identity-provider-redirector: the stock
# authenticator redirects to /broker/{alias}/login first. This flow always forces exactly one IDP.
# sekidp-direct-redirector always targets zeta-sekidp-oidc.

REALM="zeta-guard"
FLOW="zeta-mobile"

# 1) Create top-level browser flow (empty)
./kcadm.sh create authentication/flows -r "$REALM" \
  -s alias="$FLOW" \
  -s providerId=basic-flow \
  -s topLevel=true \
  -s builtIn=false \
  -s "description=ZETA mobile: enforced redirect to the SekIDP"

# 2) Add the SekIDP Direct Redirector as the only execution
./kcadm.sh create "authentication/flows/$FLOW/executions/execution" -r "$REALM" \
  -b '{"provider":"sekidp-direct-redirector"}'

# 3) Determine the execution id (the flow has exactly one execution → first "id").
EXEC_ID=$(./kcadm.sh get "authentication/flows/$FLOW/executions" -r "$REALM" | jq -r '.[0].id')
echo "   execution id: $EXEC_ID"
if [ -z "$EXEC_ID" ]; then
  echo "❌ Could not determine the execution id for flow '$FLOW' — aborting."
  exit 1
fi

# 4) Set the redirector to REQUIRED
./kcadm.sh update "authentication/flows/$FLOW/executions" -r "$REALM" \
  -b "{\"id\":\"$EXEC_ID\",\"requirement\":\"REQUIRED\"}"
