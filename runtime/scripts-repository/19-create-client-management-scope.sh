#!/bin/bash
set -eo pipefail

echo "🛠️ Create ZETA client-management client scope (zeta:client-management)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping client-management client scope (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

# Authorizes the PEP-protected endpoints a mobile client uses to list/delete the clients of its identity and
# to change its email. Like the email-binding scopes it is only CREATED here and assigned as an OPTIONAL
# client scope to mobile clients during DCR by ZetaGuardClientRegistrationPolicy — deliberately NOT a realm
# default, so stationary (SMC-B) clients never carry it. "include.in.token.scope" must be true so the PEP can
# check the scope value. The scope carries its own copy of the claim mapper so a token requested with this
# scope alone still has the ZETA claims. The Guard audience is a deployment property and is configured by
# the deployment tooling, not here.
./kcadm.sh create client-scopes -r zeta-guard \
  -s "id=zeta:client-management" \
  -s "name=zeta:client-management" \
  -s protocol=openid-connect \
  -s "description=ZETA scope for managing the clients and email of the caller's identity" \
  -s 'attributes."include.in.token.scope"=true' \
  -s 'attributes."display.on.consent.screen"=false'

SCOPE_ID=$(./kcadm.sh get client-scopes -r zeta-guard | jq -r '.[] | select(.name=="zeta:client-management") | .id')

./kcadm.sh create "client-scopes/$SCOPE_ID/protocol-mappers/models" -r zeta-guard \
  -s id=zeta-guard-mapper-client-management \
  -s name=zeta-guard-mapper \
  -s protocol=openid-connect \
  -s protocolMapper=zeta-guard-accesstoken-mapper \
  -s 'config."access.tokenResponse.claim"=true' \
  -s 'config."access.token.claim"=true' \
  -s 'config."id.token.claim"=true' \
  -s 'config."introspection.token.claim"=true' \
  -s 'config."userinfo.token.claim"=true'
