# **Keycloak Token Exchange Example using cURL**

This guide demonstrates the OAuth 2.0 Token Exchange feature (RFC 8693\) in Keycloak.

https://www.keycloak.org/securing-apps/token-exchange

We will use curl to perform the following flow:

1. A user authenticates with an initial client (initial-client) and gets an access token.
2. A backend service/client (requester-client) takes this access token.
3. The backend client (requester-client) "exchanges" the user's token for a new access token that is intended for a different service/client (target-client).

This is useful in microservices architectures where a service might need to call another service on behalf of the user.

## **Prerequisites**

Before running the token-exchange.sh script, you need to configure your Keycloak realm.

1. **A running Keycloak instance.** The script assumes it's running at http://localhost:8080.
2. **A realm.** The script uses a realm named "zeta-guard".
3. **A user.** A standard user is needed to log in. The script uses "user1" with the password "password".
4. **Three clients:**
    * **initial-client (Public Client):** This client represents the initial application the user logs into.
        * **Client ID:** initial-client
        * **Client Authentication:** Off
        * **Direct access grants:** On
        * **Valid Redirect URIs:** \* (or +)
    * **requester-client (Confidential Client \- The Exchanger):** This client will perform the token exchange.
        * **Client ID:** requester-client
        * **Client Authentication:** On
        * **Authorization:** On
        * **Authentication flow:** Enable "Token exchange"
        * Get the Client Secret from the "Credentials" tab and paste it into the script.
    * **target-client (Confidential Client \- The Target Audience):** This client represents the target service that will accept the new token.
        * **Client ID:** target-client
        * **Client Authentication:** On
      * Get the Client Secret from the "Credentials" tab and paste it into the script.
5. **Client scopes**: Necessary to map the "aud" claim into the access token
    * **audience-requester-scope:** This scope will add the client "requester-client" as an audience to the access token
        * "Type" = "Optional" 
        * **Mappers:** Add a mapper of type "Audience" named "requester-client-audience-mapper"
          * "Included Client Audience" = "requester-client" 
          * "Add to access token" = "ON" 
    * **audience-target-scope:** This scope will add the client "target-client" as an audience to the access token
        * "Type" = "Optional" 
        * **Mappers:** Add a mapper of type "Audience" named "target-client-audience-mapper"
          * "Included Client Audience" = "target-client"
          * "Add to access token" = "ON"
6. Update clients
    * Add client scope "audience-requester-scope" to client "initial-client"
    * Add client scope "audience-target-scope" to client "requester-client"
7. Create a user "user1" in the realm
    * Email verified "enabled"
    * Create Credentials password "password" (Temporary off)

## **How to Run**

1. Ensure jq is installed (sudo apt-get install jq or brew install jq). It is used to parse JSON responses.
2. Update the variables in token-exchange.sh to match your Keycloak setup.
4. Run the script: ./token-exchange.sh.

The script will print the initial token, the exchanged token, and an introspection of both tokens to show the difference, particularly in the aud (audience) claim.
