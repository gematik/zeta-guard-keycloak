#!/bin/bash

enabled="${SPREE_INTEGRITY_ENABLED:-false}"
json="attributes={\"spree.config.realm.enable.integrity-provider\":\"${enabled}\"}"

echo "🛠️ Configure Spree Integrity provider for ${SPREE_ENCRYPTED_REALM}: ${enabled}"

./kcadm.sh update "realms/${SPREE_ENCRYPTED_REALM}" -s "$json"

