#!/bin/bash

echo "🛠️ Setup ZETA SekIDP identity provider (mobile / GesundheitsID)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping SekIDP identity provider (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

# Registers only the IdP *instance* (alias zeta-sekidp-oidc) in the realm — NO contact with the SekIDP.
# The SekIDP network call itself is stubbed in the provider (SEKIDP_MOCK_ENABLED). Headless brokering via
# updateProfileFirstLoginMode=off + a headless first-broker-login flow (only "Create User If Unique", no
# review profile). The redirect to the SekIDP is enforced by the zeta-mobile browser flow
# (see 14-create-mobile-browser-flow.sh), which is set on mobile clients during DCR as a browserFlow override.

REALM="zeta-guard"
FBL="zeta-mobile-first-login"

# 1) Create the headless first-broker-login flow FIRST — the IdP references it via firstBrokerLoginFlowAlias,
#    so it must exist before the IdP is created (a flow reference cannot point to a non-existent flow).
#    Only "Create User If Unique", NO review profile: otherwise the default "first broker login" flow enforces
#    the review-profile/VERIFY_PROFILE page and the headless mobile flow cannot complete.
./kcadm.sh create authentication/flows -r "$REALM" \
  -s alias="$FBL" \
  -s providerId=basic-flow \
  -s topLevel=true \
  -s builtIn=false \
  -s "description=ZETA mobile headless first broker login (only Create User If Unique)"

./kcadm.sh create "authentication/flows/$FBL/executions/execution" -r "$REALM" \
  -b '{"provider":"idp-create-user-if-unique"}'

FBL_EXEC=$(./kcadm.sh get "authentication/flows/$FBL/executions" -r "$REALM" \
  | grep '"id"' | head -1 | sed -E 's/.*"id"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/')
echo "   first-broker-login execution id: $FBL_EXEC"
if [ -z "$FBL_EXEC" ]; then
  echo "❌ Could not determine the execution id for flow '$FBL' — aborting."
  exit 1
fi
./kcadm.sh update "authentication/flows/$FBL/executions" -r "$REALM" \
  -b "{\"id\":\"$FBL_EXEC\",\"requirement\":\"REQUIRED\"}"

# 2) Create the IdP. sekidp-identity-provider.json already points firstBrokerLoginFlowAlias at the flow above,
#    so no later "switch the IdP over" step is needed.
#
#    NOTE on validateSignature="false" in that file: it does NOT mean the ID token signature is unchecked.
#    SekIDPIdentityProvider overrides verify() and always validates, against the protocol keys resolved from
#    the SekIDP's signed_jwks_uri through the federation trust chain. The flag stays "false" because it only
#    steers Keycloak's own key resolution (jwksUrl / publicKeySignatureVerifier), which cannot express a
#    SIGNED JWK set — and because the admin API REJECTS creating the IdP with validateSignature="true" while
#    neither of those is set ("The 'Validating public key' is required ..."), i.e. this script would fail.
./kcadm.sh create identity-provider/instances -r "$REALM" -f "$KC_DIR"/scripts/sekidp-identity-provider.json
