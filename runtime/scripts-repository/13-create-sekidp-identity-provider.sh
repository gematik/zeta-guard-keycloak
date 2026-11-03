#!/bin/bash

echo "🛠️ Setup ZETA SekIDP identity provider (mobile / GesundheitsID)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping SekIDP identity provider (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

REALM="zeta-guard"

# Registers the IdP instance
# The provider creates user and Federated Identity itself (A_29671).
# validateSignature="false" only disables Keycloak's own key lookup; SekIDPIdentityProvider.verify() always
# checks the ID token against the federation trust chain.
./kcadm.sh create identity-provider/instances -r "$REALM" -f "$KC_DIR"/scripts/sekidp-identity-provider.json
