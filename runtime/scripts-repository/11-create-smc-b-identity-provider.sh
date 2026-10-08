#!/bin/bash
set -eo pipefail

echo "🛠️ Setup 𝛇-Guard identity provider"

./kcadm.sh create identity-provider/instances -r zeta-guard -f "$KC_DIR"/scripts/smc-b-identity-provider.json
