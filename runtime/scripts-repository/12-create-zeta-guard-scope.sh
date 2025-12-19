#!/bin/bash

echo "Create and configure 𝛇-Guard client scope"

./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/zeta-guard-scope.json

# OR: ./kcadm.sh get client-scopes -r zeta-guard --query search=zeta-guard-scope --fields id,name --format json |jq -r '.[] | select (.name=="zeta-guard-scope") | .id'
SCOPE_ID=$(./kcadm.sh get client-scopes -r zeta-guard --fields id,name --format csv --noquotes | grep "zeta-guard-scope" | awk -F, '{print $1}')
echo "New Scope ID: $SCOPE_ID"

./kcadm.sh update "realms/zeta-guard/default-default-client-scopes/$SCOPE_ID" -b "{}"
