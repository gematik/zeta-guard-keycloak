#!/bin/bash

echo "Create client scopes for integration tests"

./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/audience-requester-scope.json
./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/audience-target-scope.json

./kcadm.sh update "realms/zeta-guard/default-optional-client-scopes/audience-requester-scope" -b "{}"
./kcadm.sh update "realms/zeta-guard/default-optional-client-scopes/audience-target-scope" -b "{}"

