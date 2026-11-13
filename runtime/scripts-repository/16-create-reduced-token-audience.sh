#!/bin/bash

echo "🛠️ Create the 𝛇-Guard AS client and use it as audience of the reduced email-binding token"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping reduced-token audience client (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

./kcadm.sh create clients -r zeta-guard -f "$KC_DIR"/scripts/zeta-guard-as-client.json

SCOPE_ID=$(./kcadm.sh get client-scopes -r zeta-guard | jq -r '.[] | select(.name=="zeta:email-verify") | .id')

./kcadm.sh create "client-scopes/$SCOPE_ID/protocol-mappers/models" -r zeta-guard \
  -s id=zeta-guard-as-audience-mapper \
  -s name=zeta-guard-as-audience-mapper \
  -s protocol=openid-connect \
  -s protocolMapper=oidc-audience-mapper \
  -s 'config."included.client.audience"=zeta-guard-as' \
  -s 'config."access.token.claim"=true' \
  -s 'config."id.token.claim"=false' \
  -s 'config."introspection.token.claim"=true'

# Same claim mapper as the Terraform scopes carry: the binding token then holds the ZETA claims the PEP needs
# (common_name, client_id, ip_address, product_*, platform) even without zero:audience.
./kcadm.sh create "client-scopes/$SCOPE_ID/protocol-mappers/models" -r zeta-guard \
  -s id=zeta-guard-mapper-zeta-guard \
  -s name=zeta-guard-mapper \
  -s protocol=openid-connect \
  -s protocolMapper=zeta-guard-accesstoken-mapper \
  -s 'config."access.tokenResponse.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."id.token.claim"=true' \
  -s 'config."introspection.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true'
