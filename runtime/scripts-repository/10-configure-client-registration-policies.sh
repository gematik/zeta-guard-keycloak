#!/bin/bash

echo "Setup 𝛇-Guard client registration policies"

./kcadm.sh get components -r zeta-guard --fields "id,providerId,parentId" > components.json

# See org.keycloak.services.clientregistration.policy.impl.TrustedHostClientRegistrationPolicyFactory
TRUSTED_HOST_ID=$(jq -r '.[] | select (.providerId=="trusted-hosts") | .id' < components.json)

# See org.keycloak.services.clientregistration.policy.impl.ConsentRequiredClientRegistrationPolicyFactory
CONSENT_REQUIRED_ID=$(jq -r '.[] | select (.providerId=="consent-required") | .id' < components.json)

# See org.keycloak.services.clientregistration.policy.impl.MaxClientsClientRegistrationPolicy
MAX_CLIENTS_ID=$(jq -r '.[] | select (.providerId=="max-clients") | .id' < components.json)

echo Resolved trusted hosts policy id is "$TRUSTED_HOST_ID"
echo Resolved consent required policy id is "$CONSENT_REQUIRED_ID"
echo Resolved max clients policy id is "$MAX_CLIENTS_ID"

./kcadm.sh delete components/"$TRUSTED_HOST_ID" -r zeta-guard
./kcadm.sh delete components/"$CONSENT_REQUIRED_ID" -r zeta-guard
./kcadm.sh delete components/"$MAX_CLIENTS_ID" -r zeta-guard

COMPONENT_ID=$(jq -r '.[] | select (.providerId=="allowed-client-templates" and .subType=="anonymous") | .parentId' < components.json)
echo Client registration component id is "$COMPONENT_ID"

./kcadm.sh create components -r zeta-guard -s name="Setup newly created 𝛇-Guard clients" \
  -s providerId="zeta-client-registration-policy" -s subType="anonymous"\
  -s providerType="org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy" \
