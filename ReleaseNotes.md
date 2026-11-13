<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png" alt="gematik"/> <br/>

# Release Notes ZETA PDP

## Release 2.0.2

### added:
- Refresh token grant (A_29843): the `scope` parameter may request scopes that were not part of the original grant.
  The new access token carries exactly the requested scopes, provided they are client scopes assigned to the client
  and the policy engine allows them; the OPA input `scopes` now reflects the requested scopes (falling back to the
  originally granted ones if `scope` is absent). Session, consent and token-reuse checks are still applied by Keycloak

### fixed:
- Mobile flow: the authserver issues KVNR tokens only within a request that passed the policy engine decision for that
  client (or for the reduced e-mail-binding token). Other grants on a SekIDP session no longer yield such tokens
- Keycloak's standard token exchange is disabled in the image; exchanges the 𝝵-Guard providers decline get HTTP 400
- The e-mail-binding token exchange requires a DPoP proof of the key its subject token is bound to
- The well-known configuration announces `response_types_supported` `code` only
- TPM attestation is disabled until the expected protocol update.
- Removed the compromised emSign/eMudhra root CAs (CVE-2026-114406 / CVE-2026-91403) from the hardened Keycloak image's 
  Java truststore (cacerts) and OS trust bundles
- The entity statement at `.well-known/openid-federation` is served with Content-Type `application/entity-statement+jwt`
  as OpenID Federation requires, instead of `application/jwt`. Requests with `Accept: application/entity-statement+jwt`
  no longer fail with 406, so a federation master can fetch it (ANFTI2-1074)
- Entity statement: optimized the query that loads the `redirect_uris`
- The client expiration job no longer removes all expired clients in a single transaction. After a load test with
  hundreds of thousands of clients that transaction exceeded the transaction timeout and was rolled back on every run,
  while memory grew until the container was killed (`OOMKilled`). A run now removes at most
  `CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE` (default `500`) entries, oldest first, and leaves the rest to the next
  run. With a large backlog, shorten `CLIENT_REGISTRATION_SCHEDULER_INTERVAL` or raise the batch size
- The client expiration job also removes the data of an expired user whose Keycloak user no longer exists (e.g. deleted in
  the admin console). Before, the removal failed every time
- The authserver starts again when a deployment sets `KC_FEATURES_DISABLED` itself. The configured features are now
  added to the hardened set instead of causing a startup failure
- The release notes of 2.0.1 listed the feature `twitter-broker` as disabled. It was never part of the hardened set, as
  it only exists in a coming Keycloak version
- Client Registration: Implemented check that `jwks`, `grant_types`, `client_name` and `token_endpoint_auth_method` are set
- Client Registration: Strip several URI values to prevent Keycloak making requests to attacker controlled targets
- Client Registration: Keycloak's native client-registration endpoints (`default`, `install`,
    `saml2-entity-descriptor`) are disabled, and the RFC 7592 update/delete operations
    (`PUT`/`DELETE`) are removed from the OIDC registration — only `POST`/`GET` on
    `/clients-registrations/openid-connect` remain. This closes the mapper type-swap on
    update (an allowed mapper type could be swapped to a disallowed one such as
    `oidc-hardcoded-role-mapper` via the update endpoint, injecting privileged roles) and
    the broad `ClientRepresentation` registration surface it relied on.
- E-mail binding and e-mail change: a one-time code only confirms the address it was sent to (`400 invalid_code` otherwise).
  Codes issued before the update are rejected the same way (lifetime 5 minutes); a resend issues a valid one

### changed:
- SM(C)-B user data according to A_26972-03: commonName and organizationName are taken unchanged from the certificate,
  without DN escaping of special characters (e.g. `Praxis Dr. Müller, Zahnarzt` instead of `Praxis Dr. Müller\, Zahnarzt`).
  This applies to the stored user data, the access-token claims `common_name`/`organization_name` and the OPA input
  `user_info`. organizationName is only taken if present in the certificate; otherwise the claim, the OPA input field
  and the user attribute are omitted instead of being set to `Unbekannt`
- Token exchange handles DPoP nonces according to RFC 9449, section 8: a DPoP proof without `nonce` is rejected with
  `use_dpop_nonce` (HTTP 400) and a fresh nonce in the `DPoP-Nonce` response header
- The SekIDP mTLS client (PAR and token requests) is provided as a Keycloak `connections-http-client` provider
  `zeta-sekidp-mtls`. It uses the same SPI configuration as the default HTTP client, plus the SekIDP keystore
- **BREAKING** Token exchange returns HTTP 400 instead of 403 for malformed or invalid requests (e.g. invalid nonce,
  grant type, x5c certificate, client attestation or posture)
- `POST .../zeta/identity/bind-email` answers `409` (`email_already_bound`) if the identity already has a verified e-mail
  address

### changed

- Logs and traces for security KPI calculation now also
  carry the attribute `user.roles` indicating a
  `Versicherter`, `Leistungserbringer` or `Unbekannt`-er
  user type.

## Release 2.0.1

### added:
- The entity statement at `.well-known/openid-federation` carries `metadata.federation_entity` with `name` and
  `organization_name` (gemSpec_IDP_Sek, Tab. 28), taken from `ENTITY_STATEMENT_CLIENT_NAME` and
  `ENTITY_STATEMENT_ORGANIZATION_NAME`
- `ENTITY_STATEMENT_REDIRECT_URIS` configures the entity statement's `openid_relying_party.redirect_uris` statically as a
  comma-separated list. Unset, they are still derived from the realm's SekIDP clients

### changed:
- **BREAKING** Hardening: Keycloak features not used by 𝝵-Guard are disabled in the image (`KC_FEATURES_DISABLED`):
  `account`, `account-api`, `ciba`, `device-flow`, `jwt-authorization-grant`, `authorization`,
  `admin-fine-grained-authz`, `impersonation`, `workflows`, `identity-brokering-api`, `twitter-broker`, and the
  `.well-known/uma2-configuration` endpoint. Their endpoints (e.g. `/realms/{realm}/account`, device and CIBA
  endpoints) return 404, their grant types are rejected with `unsupported_grant_type`

## Release 2.0.0

### changed:
- **BREAKING** The SekIDP federation master URL is no longer read from the identity provider config map (`fedmasterUrl`).
  It is now resolved from a provisioned `federation-master.json` file pointed to by the new environment variable
  `FEDERATION_MASTER_LOCATION` (A_29737). Deployments with `ZETA_OIDC_FLOW_ENABLED=true` must set this variable and
  provide the file; otherwise Keycloak will fail to start.
- E-mails sent by the authserver (verification code, notice to the previous address after an e-mail change) are in German
- Updated dependency of VAU Integrity Provider to 2.0.10, for better performance and improved security. If the 
  provider is enabled for a VAU deployment: **no rolling update**, make sure to shut down all cluster nodes running 
  older software releases before starting the first node with the current release!
- OPA input `client_registration_data.registration_timestamp` (and `client_registration.datetime` of the security event
  `authn_token_created`) is now the time of the initial client registration instead of the client's last access, as
  defined by `policy-engine-client-data.yaml`. It is now also converted to epoch seconds in the server's time zone; before,
  it was off by the UTC offset (e.g. two hours in the future with `Europe/Berlin`)
- **BREAKING** `GET /realms/{realm}/zeta/userinfo/email?id=<KVNR>` is no longer a stub: it returns the user's email,
  and only once it is verified. The calling resource server must authenticate with an mTLS client certificate trusted
  by the resource server truststore, otherwise it gets 401. A missing or malformed KVNR in `id`, an unknown user or an
  unverified email all get the same 404. See [Environment variables](docs/references/Environment_variables.md#resource-server-access-to-userinfoemail).
- the two log lines Keycloak's `nginx` x509cert-lookup writes for every resource server call ("No issuer certificate
  …" and the misleading "Impossible to rebuild end user cert chain …") are demoted to DEBUG via a Quarkus log filter
  in `conf/quarkus.properties`. Only these two messages of `NginxProxySslClientCertificateLookup` are affected; add
  `org.keycloak.services.x509.NginxProxySslClientCertificateLookup:debug` to `KC_LOG_LEVEL` to see them again.
- bump version of spree-integrity-provider (SIP) to 2.0.9, with better support for composite keys; includes DB migration
- **BREAKING** no longer accept dpop-tokens without nonce. Nonce value has to be the same as in the rest of the requests.
  Client-SDK is already compliant.
- JWTs with `crit` or `cty` header parameters are now rejected across token exchange (subject token + client assertion), 
  email change und SekIDP federation (A_27802-03)
- MariaDB JDBC driver for Keycloak bumped to version 3.5.9 via override of Jar-Files in the OCI image (CVE-2026-55856, CVE-2026-55857, CVE-2026-55858)
- Netty dependencies for Keycloak bumped to version 4.1.139 via override of Jar-Files in the OCI image
- BouncyCastle dependencies for Keycloak bumped to version 1.86 via override of Jar-Files in the OCI image
- **BREAKING** SekIDP login (A_26973-03): `common_name` in the access token of an insured person is now the display name from
  the ID-token claim `urn:telematik:claims:display_name` instead of the KVNR; an ID token without this claim is rejected. The
  OPA input `user_info.commonName` carries the same value. The identity provider's `defaultScope` must additionally contain
  `urn:telematik:geburtsdatum` (`urn:telematik:display_name urn:telematik:versicherter urn:telematik:geburtsdatum openid`).
- the Apple and Google (Android Key Attestation) truststores and the Google certificate status list
  (`GOOGLE_CERTIFICATE_STATUS_LOCATION`) are now reloaded like the SMC-B, TPM and OCSP truststores: checked every
  `TRUSTSTORE_RELOAD_INTERVAL` and adopted without a restart when a file changed (switched off by
  `TRUSTSTORE_RELOAD_ENABLED=false`). All truststores are loaded once by the new SPI `zeta-guard-trust-material`
  (plugin jar `zeta-commons-plugins.jar`) and shared by token exchange and client registration; a missing or
  unparsable file still fails the startup.
- **BREAKING** `POST .../zeta/identity/email` no longer accepts a `Client-Assertion`; it is reachable only through the PEP
  (see added). The e-mail binding of the registration (`identity/bind-email`, `/resend`, `/verify`) is served behind the PEP
  as well: the binding token carries the Guard audience and ZETA claims via mappers on `zeta:email-verify`, the authserver
  takes the caller from `zeta-client-data`. Deploy the chart (PEP routes, Terraform mappers) before this image.
- Session revocation: reporting a token now also ends an offline session with the same session id, not only the online
  one. Otherwise the offline session could keep refreshing tokens after the block expired.
- PKCS#12 truststores without any entries with friendly names (aliases) are now rejected at startup instead of failing
  later when a certificate is looked up
- Jackson dependencies (`jackson-core`, `jackson-databind`) for Keycloak bumped to version 2.21.7 via override of Jar-Files in the OCI image (CVE-2026-68494, CVE-2026-68497, CVE-2026-89425, CVE-2026-91776, CVE-2026-91777, CVE-2026-89407, CVE-2026-19032, CVE-2026-77310, CVE-2026-83557)
- Jackson dependencies for Keycloak bumped to version 2.21.7 via override of Jar-Files in the OCI image

### added:
- Client data according to `policy-engine-client-data.yaml` is stored in `ZETA_CLIENT_DATA` (A_26585-02): platform,
  product id and version, device info (os, os version, device model) and the attestation timestamp, taken from the client
  statement of the last successful authentication
- Session data is stored in the PDP database (A_26586-01): `ZETA_CLIENT_DATA.SESSION_DATA` holds the policy engine input
  (`policy-engine-input.yaml`) of the client's last successful authentication or refresh. It is deleted together with the
  client. Both use new nullable columns, added by an additive Liquibase migration
- OPA input `client_registration_data.attestation_timestamp` from the client statement
- Implemented Apple App Attestation for client registration (DCR), mostly following [Apple Guide](https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide)
- **BREAKING:** New required Environment variables `APPLE_KEYSTORE_LOCATION` and `APPLE_KEYSTORE_PASSWORD` (PKCS#12 truststore containing the
    Apple App Attest root CA). See Helm chart documentation for details.
- Implemented Android Key Attestation for client registration (DCR), following [Android Guide](https://developer.android.com/privacy-and-security/security-key-attestation#verifying):
  certificate chain, attestation challenge, hardware-backed key (TEE/StrongBox), locked bootloader and verified boot state
- **BREAKING:** New required Environment variables `GOOGLE_KEYSTORE_LOCATION`, `GOOGLE_CERTIFICATE_STATUS_LOCATION` and `GOOGLE_KEYSTORE_PASSWORD` (PKCS#12 truststore containing the
    Google Hardware Attestation root CAs). See Helm chart documentation for details.
- **BREAKING** Implemented software attestation for client registration (DCR) (gemSpec_ZETA 5.3.2.3.3): the client data
  signature `signed_hash_puk_client_sig` is verified, and a valid server nonce is mandatory.
- Client management for mobile clients, served behind the PEP with the scope `zeta:client-management` (assigned as a
  default scope at registration), used by the ZETA SDK: `GET /realms/{realm}/zeta/clients` lists the identity's devices
  (`client_id`, `name`), `DELETE .../clients/{client_id}` removes one, e.g. a lost device (the Keycloak client and the
  ZETA data are deleted; its sessions are ended, and once the deletion has committed, their session ids are blocked on
  the revocation stream so that enforcement points reject the device's remaining access tokens), `POST .../identity/email` with
  `/verify` and `/resend` changes the identity's e-mail address, confirmed by a one-time code sent to the new address.
  The authserver takes the caller from the PEP header `zeta-client-data` and checks no token itself; errors are problem+json.
- Client management notifications by e-mail: N1 `client_added` when another client is bound to an identity
  with a verified address, N3 `client_removed` when a client is deleted by the user or removed by ZETA Guard (expiration,
  maximum number of clients, pending clients after an e-mail change), N5 `email_changed` to the previous address. They are
  fired as ZETA-marked Keycloak events (`CLIENT_REGISTER`, `REVOKE_GRANT`, `UPDATE_EMAIL` with detail `zeta_event`) and
  sent once the change has committed
  **The realm must list the new event listener `zeta-guard-notifications` in `eventsListeners`**, otherwise no
  notifications are sent; the existing notice of the previous address after an e-mail change now depends on it too.
- The security event `authn_client_deleted` is now also logged when the user deletes a client (`user_request`), for
  expired clients (`expired`) and for clients removed after an e-mail change (`email_change_pending`), not only when the
  maximum number of clients is exceeded. See [Telemetry](docs/references/Telemetry.md).
- Client management calls are logged as admin events: deleting a client (`DELETE` on `CLIENT`), the
  e-mail change (`UPDATE` on `USER`) and binding another client to an existing identity (`CREATE` on `CLIENT`), with the
  end user and the calling client as actor and the detail `zeta_event`; `zeta_user` names the identity by its ZETA user id (the Keycloak username).
  They reach the event store if admin events are enabled, and the realm's event listeners, i.e. the admin event log of the PDP database (`zeta-guard-admin-events`).
- Client policy executor `zeta-outer-par` (A_29660): the outer PAR request of the SekIDP flow must carry all required values
- New plugin `mobile-authorization-endpoint` and authenticator `SekIdpDirectRedirectAuthenticator`: in
  the `zeta-mobile` browser flow the user is redirected directly to the sectoral IDP, without Keycloak's
  intermediate redirects relying on cookies.
- API Version 2.0.0 listed in authserver well-known
- Configuration `KC_SPI_REALM_RESTAPI_EXTENSION__ZETA__RESOURCE_SERVER_TRUSTSTORE_FILE` / `_PASSWORD`: truststore
  dedicated to resource servers calling `userinfo/email`. It defaults to Keycloak's HTTPS truststore
  (`KC_HTTPS_TRUST_STORE_FILE` / `_PASSWORD`). The client certificate is read via Keycloak's `x509cert-lookup` SPI
  (TLS connection or an ingress header).
- SekIDP login (A_26973-03): the consent-dependent ID-token claim `birthdate` (YYYY-MM-DD) is passed into the access
  token as `birthdate`, from where the PEP writes it into `ZETA-User-Info`. A missing claim is no error; a value that is
  no valid YYYY-MM-DD date is dropped with a warning.
- SekIDP login (A_26973-02): the user data of the ID token — KVNR, display name, birthdate, profession OID and organization —
  is now stored at the user as attributes `zetaguard.mobileuser.*`, encrypted by the integrity provider when it is enabled.
  It is synchronised on every login: a claim the ID token no longer carries, e.g. the birthdate after a withdrawn consent,
  is removed. While the enabled integrity provider is not yet running, the login is refused with HTTP 503.

### fixed:
- the refresh token's `exp` (and `refresh_expires_in`) no longer outlives the user session behind it: it is capped at
  the realm's SSO session limits, so a refresh before `exp` no longer fails with "Session not active".
  Rotation no longer extends it either — the session ends with the first refresh token's `exp` after full
  authentication (A_25662). Realm session limits must be at least the policy's refresh-token TTL.
- the maximum number of clients per user (`SMCB_USER_MAX_CLIENTS`, A_25748-02) now also holds for concurrent token
  exchanges, across all Keycloak instances. Previously, concurrent requests of the same user could exceed the limit,
  or, with the limit reached, all but one of them were rejected with "Too many clients" instead of evicting the oldest
  client. Binding a new client now locks the user's row in `ZETA_USER_DATA`, so such requests are serialized, and a
  user who already exceeds the limit is brought back to it with the next new client.
- OPA input `user_info` now follows `zeta-user-info.yaml` of ZETA 2.0.0: it carries every value that is written into the
  access token. For SMC-B token exchange (and its refresh), `commonName` and the new `organizationName` hold the SMC-B
  certificate's CN and O, the values of the token claims `common_name` and `organization_name`; before, both were
  missing. For the SekIDP login (and its refresh), the new fields `organizationName` (`urn:telematik:claims:organization`)
  and `birthdate` (only with the user's consent) are added. Policies can now base their decision on these values.

## Release 1.3.2

### changed:
- bumps the BouncyCastle dependencies shipped with Keycloak
- return HTTP 400 instead of 403 for a malformed/invalid client assertion claim, e.g. `client_statement` sent as a JSON string instead of an object (A_26661)
- disable Keycloak HTTP-server metrics binder — arbitrary HTTP methods could grow `http_server_requests` unbounded → OOM (CVE-2026-40984)
- **BREAKING** fixed inconsistent upper-/lowercase table and column references in the
  `ZETA_USER_DATA`/`ZETA_CLIENT_DATA` Liquibase migration (`jpa-changelog-26.6.3.xml`),
  which broke on case-sensitive databases (MariaDB). Editing the already-applied
  changesets in place changes their Liquibase checksums — **existing deployments must,
  before upgrading, drop the `ZETA_USER_DATA`/`ZETA_CLIENT_DATA` tables AND delete the
  file's Liquibase bookkeeping** — the plugin migrations track state in their own
  `databasechangelog_zeta_guard` table, and dropping the tables alone is not enough (the
  stored checksums still fail validation):
  ```sql
  DROP TABLE IF EXISTS zeta_client_data, zeta_user_data CASCADE;
  DELETE FROM databasechangelog_zeta_guard WHERE filename LIKE '%jpa-changelog-26.6.3%';
  ```
  On startup this release then re-runs the whole changelog and recreates both tables.
  A `validCheckSum` workaround was deliberately not used.

## Release 1.3.1

### changed:
- bump version of spree-integrity-provider (SPI) to 2.0.5

## Release 1.3.0

### added:
- OPA input `device_info` (os, os_version, device_model) filled from the attested client statement
- Extend OPA input by amr and acr
- Session revocation: new realm resource at
  `.../realms/{realm}/zeta-guard-revocation`. `POST` an access token (`text/plain`) to
  report it as compromised — it is decoded against the realm's keys, so a foreign or
  unsigned token cannot revoke anything; the session id is blocked until the token's own
  `exp` and the session is ended through Keycloak. `GET` subscribes to the block list as
  server-sent events: the connect delivers a snapshot before deltas, so a reconnect
  doubles as reconciliation and no catch-up endpoint is needed.
  Blocks live in a `zetaGuardRevocations` Infinispan cache keyed by session id. Embedded
  mode declares the cache at startup; dedicated-Infinispan (`clusterless`) deployments
  must provide it themselves, and the provider probes the cache on boot so a missing one
  fails startup instead of answering 500s to reports nobody receives.
  **The realm must list `zeta-guard-revocation-events` in `eventsListeners`** — without
  it only the report endpoint produces blocks, and logouts, grant revocations and admin
  session deletions go unnoticed.
  Sessions that merely reach the end of their own lifetime produce no block: nothing
  withdrew trust ahead of schedule and the remaining exposure is bounded by the `exp`
  that enforcement points already check.
  Blocks derived from an event (logout, grant revocation, admin session deletion) are
  held for a flat hour (assuming no policy grants tokens for longer than that), rather
  than the token's own lifetime: the access token TTL is decided per exchange by the OPA
  policy (`access_ttl`) and kept in a session note that dies with the session, so it is
  not knowable once the session is gone.
- the SMC-B, TPM and OCSP truststores and their meta files are checked every `TRUSTSTORE_RELOAD_INTERVAL`
  (default `PT1H`) and adopted without a restart when the files changed.
- security event `authn_client_deleted` when a client registration is deleted because the
  maximum number of clients per SMC-B user was exceeded (see `docs/references/Telemetry.md`)
- require certificate meta files, support expired CAs, enforce TSP binding
- OTel integration for fraud detection
- added security event logging for client registration and token exchange 
- configurable OCSP request timeout and optional fail-closed mode (`ocspFailClosed`, default off) for the SMC-B revocation check
- Netty dependencies for Keycloak bumped to version 4.1.136 via override of Jar-Files in the OCI image
- ENV-VAR `ZETA_OIDC_FLOW_ENABLED` (default `false`) — master switch for the OIDC client flow; off by default, so existing deployments behave as before
- identity provider `zeta-sekidp-oidc`: the sectoral IDP is chosen per request via `idp_iss`, its PAR, authorization
  and token endpoints are taken from the IDP's entity statement, and the trust chain is resolved through the
  Federation Master.
- the guard's entity statement at `/realms/{realm}/.well-known/openid-federation`, a compact JWS signed with the
  realm's active ES256 key and typed `entity-statement+jwt`, carries these fields:
  - `iss`/`sub` (realm URL), `iat`/`exp` , `authority_hints` (Federation Master)
  - `jwks` — only the key that self-signs the statement
  - `metadata.openid_relying_party` with `redirect_uris`, `response_types=code`, `grant_types=authorization_code`,
    `client_registration_types=automatic`, `require_pushed_authorization_requests=true`,
    `token_endpoint_auth_method=self_signed_tls_client_auth`, `id_token_signed_response_alg=ES256`,
    `id_token_encrypted_response_alg=ECDH-ES`, `id_token_encrypted_response_enc=A256GCM`, `scope` (the SekIDP
    validates the PAR scopes against it, A_29660) and `jwks` with the ECDH-ES key for the encrypted ID token
- `authorization_code` grant for mobile clients: OPA authorizes the token issuance, and a client whose e-mail binding
  is not yet confirmed receives a reduced e-mail-binding token instead of the full token set — 300 s lifetime, no
  refresh token, `binding_mode=collect_email|verify_otp` in the token response, plus `email_hint` for `verify_otp`
- e-mail binding endpoints `POST /realms/{realm}/zeta/identity/bind-email`, `.../bind-email/resend` and
  `.../bind-email/verify`, reachable with the reduced token: a 6-digit OTP valid for 300 s is mailed to the submitted
  address (`collect_email`) or to the address already bound to the identity (`verify_otp`)
- token exchange `zeta-email-binding-token-exchange`: swaps the reduced binding token for the full token set once the
  binding is confirmed, restoring the scopes originally requested via PAR
- identity-scoped e-mail change `POST /realms/{realm}/zeta/identity/email`, authorized by a `Client-Assertion` header
  bound to the request method and URI (A_29911, A_30101); the previous address is notified about the change (A_25750)
  and sibling registrations of the same identity with an open OTP challenge are removed
- `GET /realms/{realm}/zeta/userinfo/email` — stub answering every identifier with a static address
- provisioning of the browser flow `zeta-mobile` (enforced SekIDP redirect, no login screen), the headless
  `zeta-mobile-first-login` flow and the client `zeta-guard-as`, the audience of the reduced binding token

### changed:
- TLS 1.3 named groups restricted to secp256r1/secp384r1 — secp521r1 is no longer negotiated
- reaching the maximum number of client registrations per SMC-B user (`SMCB_USER_MAX_CLIENTS`,
  default 256) no longer rejects the new registration: the least-recently-used registration of
  that user is deleted instead, so the current registration can proceed (A_25748-02)
- the DPoP reference/test token generator now embeds a minimal JWK (`kty`/`crv`/`x`/`y` only),
  dropping the optional `alg`/`kid`/`use` members so the proof matches the DPoP schema
- updated Keycloak to 26.6.4
- the SMC-B reference/test token generator no longer emits `header.kid` or the `payload.typ`
  (`Bearer`) claim, so the subject token matches subject-token-smb.yaml
- the OPA gate now also covers the `authorization_code` grant; mobile sessions carry their own OPA context, which the
  refresh-token grant replays and the access-token mapper reads for the PDP TTLs (A_28527)
- the policy input of the refresh-token grant now carries `posture_type`, which so far only reached OPA on the
  token-exchange path
- the `zeta-guard` realm provisions an `ecdsa-generated` (P-256) and an `ecdh-generated` (ECDH-ES) key provider —
  required for signing the entity statement and for decrypting the SekIDP's ID token
- the access-token mapper serves both SMC-B and mobile sessions; for mobile sessions the KVNR becomes the token
  subject and the client statement supplies the product claims
- dynamic client registration: a client registering with redirect URIs is set up as a mobile client — mobile browser
  flow override, e-mail-binding client scopes and standard token exchange. NOTE: its attestation is not evaluated yet,
  every mobile registration passes and receives a mocked client statement
- `ZETA_CLIENT_DATA` gains the columns `CLIENT_AUTH_METHOD` (default `SMC_B`) and `CLIENT_REGISTRATION_STATUS`;
  the migration is additive and safe for a rolling upgrade
- the `VERIFY_PROFILE` required action is disabled in the `zeta-guard` realm
- updated spree integrity provider (SPI) to version 2.0.3
- bump BouncyCastle to 1.85

## Release 1.2.3

### changed:
- token exchange now enforces the SMC-B-signed `client_key`/`dpop_key` bindings; mismatched keys are rejected with `invalid_token`
- bump integrity provider to 1.3.3

## Release 1.2.2

### changed:
- fix crash when restart with dbEnc enabled

## Release 1.2.1

### changed:
- bump integrity provider to the public release version
- updated to new policy api schema

## Release 1.2.0

### added:
- HSM token signing: refuse software-key fallback when HSM is enabled but unreachable (SPI option `failClosed`, default true); 
  token-exchange returns `503 temporarily_unavailable` with `Retry-After: 30`
- OPA policy enforcement on the refresh-token grant: each refresh authorizes via OPA before issuing a new token set; 
  OPA-unreachable returns `503 temporarily_unavailable` with `Retry-After: 30`
- Client assertion JWT `typ` header validation (`typ=JWT` required per A_25338-01); invalid values are rejected with `400 invalid_request` during client authentication
- SMC-B certs are now subject to OCSP checks


### changed:
- Keycloak upgraded to 26.6.3
- HSM JCA provider registration moved from runtime (`KeyProviderFactory.postInit()`) to JVM init via
  `-Xbootclasspath/a:` set up in `startup.sh`. Required by Quarkus 3.33's TLS Registry, which resolves `HSMPROXY` before
  any Keycloak SPI initializes.
- Fixed: platform product id in client statement is now optional for Software and TPM attestation
- Fixed: audience parameter is now required on token exchange
- Fixed: audience claim of smc-b tokens is now required to equal the URL of the token endpoint
- Fixed: typ claim of smc-b tokens is now not required to be "Bearer" anymore 
- Fixed: "urn:telematik:client-self-assessment" is not required anymore in client assertion jwt
- Fixed: oauth-authorization-server Well-Known document now conforming to schema. Especialle the registration endoint is
  now present.
- Fixed: DPoP is now required for refresh tokens.
- Fixed: OPA-Simulation call is not blocking anymore.
- No-HSM startup mode restored — `startup.sh` no longer aborts when HSM env vars are unset (Scenario 1 in `runtime/compose.yaml`).
- Aligned policy input with schema policy-engine-client-data.yaml v1.3.0

### removed:

- OPA: `opaEnabled` and `failClosed` config keys — enforcement is always on and fail-closed

## Release 1.0.1-dbEnc

### added:
- database encryption added in this release (for VAU only)
- database integrity check added in this release, but disabled by default (for VAU only)

## Release 1.0.1

### added:
- security hotfixes and CVE tracking

### changed:
- improved CI structure for security hotfixes


## Release 1.0.0

### added:
- HSM-backed token signing (`hsm-token-signing` plugin) — access tokens, ID tokens, and refresh tokens signed with ES256 via HSM
- HSM KeyProvider configurable via Admin UI (Realm Settings → Keys → Providers → zeta-hsm-token-signing)
- `productID` and `productVersion` from the client attestation are now forwarded to OPA and verified against the `allowed_products` policy data

### changed:
- OPA simulation calls run asynchronously (bounded fire-and-forget executor) — shadow evaluations no longer block the active OPA decision path

## Release 0.5.1

### added:
- Integration of `java-hsm-proxy-provider` (`hsm-proxy-provider` plugin)
- TLS via HSM support (Quarkus/Keycloak configuration)

### changed:
- Keycloak upgraded to 26.5.7

## Release 0.5.0

### changed:
- Parse Forwarded headers for impossible travel detection

## Release 0.4.1

### changed:
- Keycloak upgraded to 26.5.6
- Improved OPA decision client logging and error handling
- Improve certificate lookup performance

## Release 0.4.0

### added:
- TPM attestation validation
- refresh token grant type `grant_type=refresh_token`
- extended access token claims
- OPA simulation instance support
- ENV-VARs
  - `SMCB_HASHING_PEPPER` — **required**; pepper for Telematik-ID hashing
  - `OPA_SIMULATION_BASE_URL` — **optional**; URL of the shadow OPA instance

### changed:
- **BREAKING** Telematik-ID no longer stored as username
- Keycloak upgraded to 26.5.5 (official release)
- authorization failures return `403` instead of `400`
- audience claim (`aud`) handling corrected

## removed
- `CHECK_CLIENT_ATTESTATION_ENABLED` for client software attestation has been removed. Attestation verification is now always enforced.

## Release 0.3.2

### changed:
- update release notes

## Release 0.3.1

### changed:
- update release notes 

## Release 0.3.0

### added:
- verification of client's software attestation (currently behind environment variable-based toggle CHECK_CLIENT_ATTESTATION_ENABLED -> do not touch for production, this toggle will be removed in the future)
- client-statement is read from client assertion JWT
- refresh token expiry is now determined by opa policies

### changed:
- more lenient OID verification for SMCB, so that all SMCBs can be used
- improved test coverage measurement

## Release 0.2.4

### added:
- mapping userdata and clientdata into access token
- more consistent license headers via maven plugin

### changed:
- minor updates and improvements

## Release 0.2.3

### changed:
- minor compliance-specific code formatting changes

## Release 0.2.2

### added:
- SBOM generation

## Release 0.2.1

### changed:
- refactoring smc-b keystore for unit tests

## Release 0.2.0

### added:
- SMC-B token exchange
- storage of user and client data
- client registration according to spec
- nonce endpoint
- ZETA-specific discovery endpoint
- OPA integration for access tokens in token exchange

## Release 0.1.2

### added:
- Prototype of the ZETA PDP added
