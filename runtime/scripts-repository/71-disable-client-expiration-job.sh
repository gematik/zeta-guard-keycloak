#!/bin/bash
set -eo pipefail

json="attributes={\"zeta-guard.realm.client_job.disabled\":\"true\"}"

echo "🛠️ (Temporarily) Disabling Client Expiration Job for realm »zeta-guard«"

./kcadm.sh update "realms/zeta-guard" -s "$json"

