#!/bin/bash

./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/audience-requester-scope.json
./kcadm.sh create client-scopes -r zeta-guard -f "$KC_DIR"/scripts/audience-target-scope.json

# No effect !? 🙄
./kcadm.sh update realms/zeta-guard -s defaultOptionalClientScopes='["audience-requester-scope", "audience-target-scope", "offline_access", "address", "phone", "microprofile-jwt", "organization"]'


