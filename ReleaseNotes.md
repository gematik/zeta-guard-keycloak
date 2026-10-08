<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PDP

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

> [!IMPORTANT]  
> The source code for this release relies on a [patched version of Keycloak](https://github.com/techatspree/keycloak), which is not yet merged into the main Keycloak repository. To build this project from source code, you will need to clone the patched Keycloak repository and build it locally using the special version tag '999.0.0-SNAPSHOT' first. 

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
