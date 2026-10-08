#!/bin/bash
set -eo pipefail

echo "🛠️ Add revocation event listener"

./kcadm.sh update events/config -r zeta-guard -s 'eventsListeners=[ "zeta-guard-admin-events", "zeta-guard-revocation-events"]'
