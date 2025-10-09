#!/bin/bash

./kcadm.sh get components -r zeta-guard --fields "id,providerId" > components.json

# See org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicyFactory
TRUSTED_HOST_ID=$(jq -r '.[] | select (.providerId=="trusted-hosts") | .id' < components.json)

# See org.keycloak.services.clientregistration.policy.impl.ConsentRequiredClientRegistrationPolicyFactory
CONSENT_REQUIRED_ID=$(jq -r '.[] | select (.providerId=="consent-required") | .id' < components.json)

# See org.keycloak.services.clientregistration.policy.impl.MaxClientsClientRegistrationPolicy
MAX_CLIENTS_ID=$(jq -r '.[] | select (.providerId=="max-clients") | .id' < components.json)

echo Resolved trusted hosts policy id is "$TRUSTED_HOST_ID"
echo Resolved consent required policy id is "$CONSENT_REQUIRED_ID"
echo Resolved max clients policy id is "$MAX_CLIENTS_ID"

#./kcadm.sh update components/"$TRUSTED_HOST_ID" -r zeta-guard -s 'config."host-sending-registration-request-must-match"=["false"]'

./kcadm.sh delete components/"$TRUSTED_HOST_ID" -r zeta-guard
./kcadm.sh delete components/"$CONSENT_REQUIRED_ID" -r zeta-guard

# A_25748 - PDP Client-Registrierung - Maximale Anzahl von Clients
# Die Komponente Authorization Server MUSS sicherstellen, dass ein Nutzer maximal 256 Clients registrieren kann. Der Wert muss konfigurierbar sein.
# TODO: Currently this policy limits the *total* number of clients
#./kcadm.sh update -r zeta-guard components/"$MAX_CLIENTS_ID" -s 'config."max-clients":["256"]'

