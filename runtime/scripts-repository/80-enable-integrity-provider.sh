#!/bin/bash
set -eo pipefail

enabled="${SPREE_INTEGRITY_PROVIDER_ENABLED:-false}"

# Trigger next step of bootstrap process by setting realm attribute "spree.config.realm.enabled"
json=(
  -s "attributes.\"spree.config.realm.enabled\"=${enabled}"
  -s "attributes.\"hibernate.cdi.extensions\"=${enabled}"
)

echo "🛠️ Configure Spree Integrity provider for ${SPREE_ENCRYPTED_REALM}: ${enabled}"

./kcadm.sh update "realms/${SPREE_ENCRYPTED_REALM}" "${json[@]}"

