#!/bin/bash

# This script demonstrates the Keycloak token exchange flow.
# See https://www.keycloak.org/securing-apps/token-exchange#_standard-token-exchange-enable

KEYCLOAK_URL="http://localhost:18080"
REALM="zeta-guard"
TOKEN_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token"
INTROSPECT_ENDPOINT="${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token/introspect"

# Client the user initially logs into (public)
CLIENT_A_ID="initial-client"
CLIENT_A_SCOPE="audience-requester-scope"

# Client performing the exchange (confidential)
CLIENT_B_ID="requester-client"
CLIENT_B_SECRET="qXpy5mlykWglKNSvs65N8sjNXRZDJDwH"
CLIENT_B_SCOPE="audience-target-scope"

# Target client for the new token (audience)
CLIENT_C_ID="target-client"
CLIENT_C_SECRET="jnG1UuQzWgQROtjhU1ku9YlsRsupzL5o"

# User credentials
USERNAME="user1"
PASSWORD="password"


# --- Helper function for pretty printing JSON ---
function pretty_print_json {
    echo "$1" | jq .
}

echo "------------------------------------------------------------------"
echo "Step 1: Get initial access token for user '${USERNAME}' with '${CLIENT_A_ID}'"
echo "------------------------------------------------------------------"

# Get the initial token using the password grant type.
# The scope parameter will cause the "aud" claim to contain the client ID "requester_client".
TOKEN_RESPONSE=$(curl -s -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=${USERNAME}" \
  -d "password=${PASSWORD}" \
  -d "client_id=${CLIENT_A_ID}" \
  -d "scope=${CLIENT_A_SCOPE}" \
  -d "grant_type=password")
INITIAL_TOKEN=$(echo "${TOKEN_RESPONSE}" | jq -r '.access_token')

if [ -z "$INITIAL_TOKEN" ] || [ "$INITIAL_TOKEN" == "null" ]; then
    echo "Failed to get initial token. Response:"
    pretty_print_json "${TOKEN_RESPONSE}"
    exit 1
fi

#TOKEN=$(echo $TOKEN_RESPONSE | sed 's/.*access_token":"//g' | sed 's/".*//g')
#echo "$TOKEN"

echo "Successfully obtained initial token:"
echo "${INITIAL_TOKEN}"
echo

echo "------------------------------------------------------------------"
echo "Step 2: Perform token exchange using '${CLIENT_B_ID}'"
echo "------------------------------------------------------------------"

# client-b exchanges the initial token for a new one with client-c as the audience.
EXCHANGE_RESPONSE=$(curl -s -X POST "${TOKEN_ENDPOINT}" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=${CLIENT_B_ID}" \
  -d "client_secret=${CLIENT_B_SECRET}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "scope=${CLIENT_B_SCOPE}" \
  -d "subject_token=${INITIAL_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "requested_token_type=urn:ietf:params:oauth:token-type:access_token" \
)
#  -d "audience=${CLIENT_B_ID}"

EXCHANGED_TOKEN=$(echo "${EXCHANGE_RESPONSE}" | jq -r '.access_token')

if [ -z "$EXCHANGED_TOKEN" ] || [ "$EXCHANGED_TOKEN" == "null" ]; then
    echo "Failed to exchange token. Response:"
    pretty_print_json "${EXCHANGE_RESPONSE}"
    exit 1
fi

echo "Successfully obtained exchanged token:"
echo "${EXCHANGED_TOKEN}"
echo


echo "------------------------------------------------------------------"
echo "Step 3: Introspect tokens to see the difference"
echo "------------------------------------------------------------------"

# Introspect the initial token. The audience should be the account client.
echo "Introspecting initial token..."
INITIAL_TOKEN_INTROSPECTION=$(curl -s -X POST "${INTROSPECT_ENDPOINT}" \
  -u "${CLIENT_C_ID}:${CLIENT_C_SECRET}" \
  -d "token=${INITIAL_TOKEN}")

echo "Initial Token Details:"
pretty_print_json "${INITIAL_TOKEN_INTROSPECTION}"
echo

# Introspect the exchanged token. The audience should now be client-c.
echo "Introspecting exchanged token..."
EXCHANGED_TOKEN_INTROSPECTION=$(curl -s -X POST "${INTROSPECT_ENDPOINT}" \
  -u "${CLIENT_C_ID}:${CLIENT_C_SECRET}" \
  -d "token=${EXCHANGED_TOKEN}")

echo "Exchanged Token Details:"
pretty_print_json "${EXCHANGED_TOKEN_INTROSPECTION}"
echo

echo "------------------------------------------------------------------"
echo "Token exchange complete."
echo "Note the 'aud' (audience) claim in the introspection results."
echo "------------------------------------------------------------------"
