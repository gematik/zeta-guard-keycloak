#!/bin/bash

./kcadm.sh create clients -r zeta-guard -f "$KC_DIR"/scripts/initial-client.json
./kcadm.sh create clients -r zeta-guard -f "$KC_DIR"/scripts/requester-client.json
./kcadm.sh create clients -r zeta-guard -f "$KC_DIR"/scripts/target-client.json
./kcadm.sh create clients -r zeta-guard -f "$KC_DIR"/scripts/zeta-client.json


