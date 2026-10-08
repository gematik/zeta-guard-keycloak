#!/bin/bash
set -eo pipefail

echo "🛠️ Create ZETA email-binding client scopes (zeta:email-binding, zeta:email-verify)"

enabled=$(printf '%s' "${ZETA_OIDC_FLOW_ENABLED:-false}" | tr '[:upper:]' '[:lower:]')
if [ "$enabled" != "true" ] && [ "$enabled" != "1" ] && [ "$enabled" != "yes" ]; then
  echo "⏭️ Skipping email-binding client scopes (ZETA_OIDC_FLOW_ENABLED=${ZETA_OIDC_FLOW_ENABLED:-false})"
  exit 0
fi

# while the user binding is not complete the reduced token is down-scoped to these scopes.
#   - zeta:email-binding → register a new email address (POST .../identity/bind-email)
#   - zeta:email-verify  → resend + verify the OTP  (POST .../identity/bind-email/resend, .../verify)
# The scopes are only CREATED here (realm-level). They are assigned as OPTIONAL client scopes to mobile
# clients during DCR by ZetaGuardClientRegistrationPolicy — deliberately NOT realm defaults, so stationary
# clients are unaffected. The authorization_code grant injects the needed ones into the reduced token at
# /token. "include.in.token.scope" must be true so the scope value ends up in the token's `scope` and the
# bind-email endpoints can check for it.
create_scope() {
  local name="$1" description="$2"
  ./kcadm.sh create client-scopes -r zeta-guard \
    -s "name=$name" \
    -s protocol=openid-connect \
    -s "description=$description" \
    -s 'attributes."include.in.token.scope"=true' \
    -s 'attributes."display.on.consent.screen"=false'
}

create_scope "zeta:email-binding" "ZETA reduced scope for registering a new user email (I3)"
create_scope "zeta:email-verify" "ZETA reduced scope for resending/verifying the email OTP (I3)"
