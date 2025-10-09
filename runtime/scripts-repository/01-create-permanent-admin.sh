#!/bin/bash

./kcadm.sh get users -r master -q username="$KEYCLOAK_USER" | jq -r .[] > admin.json

ADMIN_ID=$(jq -r .id < admin.json)

echo Resolved admin id is "$ADMIN_ID"
#
#jq 'del(.attributes)' < admin.json > admin_new.json
#
#./kcadm.sh update -r master users/"$ADMIN_ID" -f admin_new.json
#
#./kcadm.sh get -r master users/"$ADMIN_ID"|less
#
#./kcadm.sh create users -r master -s username=admin -s enabled=true
#./kcadm.sh set-password -r master --username admin --new-password "$KEYCLOAK_PASSWORD"
#./kcadm.sh get users -r master -q username=admin --fields=id | jq -r .[].id
#
#./kcadm.sh add-roles -r master --uusername admin \
#  --cclientid realm-management \
#  --rolename manage-users \
#  --rolename view-users \
#  --rolename manage-realm
