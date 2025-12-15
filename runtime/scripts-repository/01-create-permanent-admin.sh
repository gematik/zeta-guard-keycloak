#!/bin/bash

./kcadm.sh get users -r master -q username="$KEYCLOAK_USER" | jq -r .[] > admin.json

ADMIN_ID=$(jq -r .id < admin.json)

echo Resolved admin id is "$ADMIN_ID"

#
#./kcadm.sh create users -r master -s username="$KEYCLOAK_USER" -s enabled=true
#
#./kcadm.sh get users -r master -q username="$KEYCLOAK_USER" | jq -r .[] > admin.json
#
#NEW_ADMIN_ID=$(jq -r .id < admin.json)
#
#./kcadm.sh set-password -r master --username "$KEYCLOAK_USER" --new-password "$KEYCLOAK_PASSWORD"
#
#./kcadm.sh add-roles -r master --uusername "$KEYCLOAK_USER"--rolename admin
#
#./kcadm.sh delete users/"$ADMIN_ID" -r master


# "attributes" : {
#    "is_temporary_admin" : [ "true" ]
#  },


# Does not work, because attribute is not "writable" (hardcoded)
#./kcadm.sh update users/$ADMIN_ID -r master -s 'attributes.is_temporary_admin=["false"]'


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
