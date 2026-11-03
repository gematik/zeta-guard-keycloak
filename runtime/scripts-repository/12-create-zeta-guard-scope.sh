#!/bin/bash
set -eo pipefail

echo "🛠️ Create and configure 𝛇-Guard client scope"

./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/zeta-guard-scope.json

SCOPE_ID=$(./kcadm.sh get client-scopes -r zeta-guard | jq -r '.[] | select(.name=="zeta-guard-scope") | .id')
echo "New Scope ID: $SCOPE_ID"

./kcadm.sh update "realms/zeta-guard/default-default-client-scopes/$SCOPE_ID" -b "{}"
