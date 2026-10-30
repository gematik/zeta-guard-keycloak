<img align="right" width="250" height="47" src="docs/img/Gematik_Logo_Flag.png"/> <br/>

# Release Notes ZETA PDP

## Release 1.2.4

### changed:
- **Hardened Dynamic Client Registration against privilege escalation (CVE-2026-15572).**
  Keycloak's native client-registration endpoints (`default`, `install`,
  `saml2-entity-descriptor`) are disabled, and the RFC 7592 update/delete operations
  (`PUT`/`DELETE`) are removed from the OIDC registration — only `POST`/`GET` on
  `/clients-registrations/openid-connect` remain. This closes the mapper type-swap on
  update (an allowed mapper type could be swapped to a disallowed one such as
  `oidc-hardcoded-role-mapper` via the update endpoint, injecting privileged roles) and
  the broad `ClientRepresentation` registration surface it relied on.

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
