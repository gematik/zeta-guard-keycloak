#!/bin/bash
set -eo pipefail

enabled="${SPREE_INTEGRITY_PROVIDER_ENABLED:-false}"

# Trigger next step of bootstrap process by setting realm attribute "spree.config.realm.enabled"
json=$(cat << __EOF__
{
  "spree.config.realm.enabled": "${enabled}",
  "hibernate.cdi.extensions": "${enabled}"
}
__EOF__
)

echo "🛠️ Configure Spree Integrity provider for ${SPREE_ENCRYPTED_REALM}: ${enabled}"

./kcadm.sh update "realms/${SPREE_ENCRYPTED_REALM}" -s "attributes=$json"

