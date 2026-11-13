# Environment variables

In addition to Keycloak's standard environment variables, the following environment variables are supported:

## Required environment variables

| Name                                 | Description                                                                                                                                                                                                                                                       |
|--------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `ENTITY_STATEMENT_CLIENT_NAME`       | Required when `ZETA_OIDC_FLOW_ENABLED=true`. `client_name` in the entity statement's `openid_relying_party` metadata and `name` in its `federation_entity` metadata (gemSpec_IDP_Sek, Tab. 28). 1 to 128 letters (umlauts included), digits, spaces and `_-.+*/`. |
| `ENTITY_STATEMENT_ORGANIZATION_NAME` | Required when `ZETA_OIDC_FLOW_ENABLED=true`. `organization_name` in the entity statement's `openid_relying_party` and `federation_entity` metadata (gemSpec_IDP_Sek, Tab. 28). Same characters as `ENTITY_STATEMENT_CLIENT_NAME`.                                 |
| `ENTITY_STATEMENT_CONTACT_EMAIL`     | Required when `ZETA_OIDC_FLOW_ENABLED=true`. Contact email in the entity statement's `openid_relying_party.contacts` list; must contain `@`.                                                                                                                      |

Keycloak does not start with the OIDC flow enabled if one of them is missing or invalid.

## Optional environment variables

| Name                                    | Default value | Description                                                                                                                                                                                 |
|-----------------------------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GENESIS_HASH`                          | random        | The seed used instead of a previous hash to calculate the first hash in the admin event log. A random string of up to 64 characters.                                                        |
| `TRUSTSTORE_RELOAD_ENABLED`             | `true`        | Whether the SMC-B, TPM, OCSP, Apple and Google truststores are reloaded while the server runs. `false` reads them only at startup.                                                          |
| `TRUSTSTORE_RELOAD_INTERVAL`            | `PT1H`        | How often the truststores are checked for changes, as an ISO-8601 duration of hours or less.                                                                                                |
| `ENTITY_STATEMENT_ID_TOKEN_VERSION`     | `1.0.0`       | Comma-separated ID-Token version(s) advertised in the entity statement's `ti_features_supported.id_token_version_supported` (A_27598), e.g. `1.0.0,2.0.0`.                                  |
| `ENTITY_STATEMENT_PRODUCT_TYPE_VERSION` | `1.0.0`       | `product_type_version` keyword in the entity statement's `openid_relying_party` metadata.                                                                                                   |
| `ENTITY_STATEMENT_REDIRECT_URIS`        | unset         | Comma-separated `redirect_uris` in the entity statement's `openid_relying_party` metadata (A_25656). Unset or empty: the redirect URIs of the realm's SekIDP clients.                       |
| `FEDERATION_MASTER_LOCATION`            | —             | Path to the `federation-master.json` file produced by the provisioning processor. The file contains a JSON object with a `fedmasterUrl` field. Required when `ZETA_OIDC_FLOW_ENABLED=true`. |
| `CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE` | `500`      | Maximum number of expired client registrations, clients and users the expiration job removes per run (each run is one transaction). A larger backlog (e.g. after a load test) is worked off over several runs, see the note below. |

> **Note:** Both `TRUSTSTORE_RELOAD_*` variables exist for test setups, where waiting an hour for a reload is not
> practical. Their defaults are the production setting — leave them alone there. Turning the reload off means new trust
> anchors only take effect on the next restart and a short interval has the server re-read several megabytes of trust
> material that often.

> **Note:** The client expiration job removes at most `CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE` entries per run, oldest first, so that the
> memory and the duration of its transaction stay bounded however many expired clients there are. What is left is removed by the next run, every
> `CLIENT_REGISTRATION_SCHEDULER_INTERVAL` (default `PT5M`), i.e. 500 clients and 500 users per 5 minutes by default. After a load test that leaves
> a large backlog, shorten the interval (e.g. `PT1M`) or raise the batch size, temporarily if need be, until the backlog is gone. A run takes
> roughly 15 seconds for 500 entries, so keep the interval well above that: the job runs on Keycloak's timer thread, which also runs other
> scheduled tasks, e.g. the keepalive of the revocation stream (every 20 s).

## Reloading the truststores

The truststores named by `SMCB_KEYSTORE_LOCATION`, `TPM_KEYSTORE_LOCATION`, `APPLE_KEYSTORE_LOCATION`, `GOOGLE_KEYSTORE_LOCATION` and `OCSP_KEYSTORE_LOCATION`, together with
the meta files next to them, are checked every `TRUSTSTORE_RELOAD_INTERVAL`. Compared is a hash over the file *bytes*.
Only when that hash moved are the files read again and parsed, and the resulting material is adopted as a whole:
requests in flight keep the truststores they started with, new requests get the new ones. No restart, no downtime.

Because the comparison is byte-based, expect one reload per provisioning run rather than one per changed certificate:
`openssl pkcs12 -export` picks a fresh salt every time, so the files differ even when the certificates do not. That is
deliberate.

If a file cannot be read or parsed or if the hash still moves between the check and the read — a provisioning run
caught between two of its result files — the material in use stays in place and the attempt is repeated at the next
interval. Both cases are logged.

This only has an effect if the files are actually rewritten at runtime. Note that single-file mounts (`subPath` on
Kubernetes, a file bind mount in Docker) pin the inode, so replacing a file by rename stays invisible inside the
container — mount the *directory* instead.

## Resource server access to `userinfo/email`

`GET /realms/{realm}/zeta/userinfo/email?id=<KVNR>` releases the *verified* email of a mobile user to a resource
server. The resource server authenticates with an mTLS client certificate, whose chain must lead to a certificate of
the resource server truststore (PKIX, validity period; no revocation check). Every certificate in the truststore is a
trust anchor: a CA certificate suffices, and a resource server certificate may be pinned directly.

| Name                                                                        | Default value                   | Description                                                                                                            |
|-----------------------------------------------------------------------------|---------------------------------|------------------------------------------------------------------------------------------------------------------------|
| `KC_SPI_REALM_RESTAPI_EXTENSION__ZETA__RESOURCE_SERVER_TRUSTSTORE_FILE`     | `KC_HTTPS_TRUST_STORE_FILE`     | Truststore dedicated to resource servers. PKCS12 (`.p12`, `.pfx`), JKS (`.jks`) or a PEM bundle (any other extension). |
| `KC_SPI_REALM_RESTAPI_EXTENSION__ZETA__RESOURCE_SERVER_TRUSTSTORE_PASSWORD` | `KC_HTTPS_TRUST_STORE_PASSWORD` | Password of that truststore; not needed for PEM.                                                                       |

Without a dedicated truststore, Keycloak's own mTLS truststore (`https-trust-store-file`/`-password`) is used. Without
either, every request is answered with 401. A configured truststore that cannot be read fails the startup. It is read
once at startup and not reloaded.

Which truststore is in use shows in the startup log:

```text
Resource server truststore »/opt/keycloak/conf/resource-server-truststore/ca.pem« (resourceServerTruststoreFile) loaded with 1 certificates
```

The value in parentheses is `resourceServerTruststoreFile` for the dedicated truststore and `https-trust-store-file`
for the fallback. With neither configured, the log shows the warning
`No resource server truststore configured, userinfo/email rejects every request` instead.

> **Note:** Do not put the resource server truststore under `conf/truststores`. Everything there also becomes trusted
> for Keycloak's *outbound* calls, and that truststore includes the public JDK CAs.

Responses carry no body: 401 for a missing or untrusted certificate (checked first), 404 for an `id` that is missing or
no KVNR (one capital letter and nine digits), an unknown user or a user without a verified email, 200 with
`{"email": "…"}` otherwise.

Where the client certificate comes from is configured with Keycloak's standard `x509cert-lookup` SPI:

| Setup                                                       | Configuration                                                                                                                                                                                                                                                                                    |
|-------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| TLS terminated by Keycloak                                  | `KC_HTTPS_CLIENT_AUTH=request` (the `default` lookup provider reads the certificate from the TLS connection)                                                                                                                                                                                     |
| TLS terminated by an NGINX ingress, certificate in a header | `KC_SPI_X509CERT_LOOKUP__PROVIDER=nginx`, `KC_SPI_X509CERT_LOOKUP__NGINX__SSL_CLIENT_CERT=ssl-client-cert`, `KC_SPI_X509CERT_LOOKUP__NGINX__TRUST_PROXY_VERIFICATION=false` (the ingress forwards the certificate unverified, `ssl_verify_client optional_no_ca`; the endpoint checks the chain) |

> **Note:** `TRUST_PROXY_VERIFICATION` must stay `false` behind an ingress that uses `optional_no_ca`. With `true`,
> Keycloak only accepts the certificate if the proxy also sends `ssl-client-verify: SUCCESS`. An ingress that does not
> verify the certificate itself never sends that, so every request would be answered with 401. With `false`, Keycloak
> tries to rebuild the certificate chain from its own (outbound) truststore. That fails for a resource server CA kept
> outside of it, so for every request carrying a client certificate `NginxProxySslClientCertificateLookup` emits a
> `WARN` "No issuer certificate for certificate in certification path found." and an `INFO` "Impossible to rebuild end
> user cert chain : client certificate authentication will fail." Both are expected and harmless, and the second is
> wrong here: the lookup still hands over the client certificate, and the endpoint validates it against the resource
> server truststore.
>
> The image demotes exactly these two messages of this one logger to `DEBUG` (Quarkus log cleanup filter in
> `conf/quarkus.properties`); all other messages, and `ERROR` in general, are untouched. To see them again, add the
> category to the log level:
> `KC_LOG_LEVEL=<current level>,org.keycloak.services.x509.NginxProxySslClientCertificateLookup:debug`.

> **Warning:** A header-based lookup is only as trustworthy as the path to Keycloak. The ingress must set the header
> itself on every request (`proxy_set_header ssl-client-cert $ssl_client_escaped_cert;`), so it overwrites whatever a
> client sent, and nothing else may be able to reach Keycloak with a forged header. Restrict that path with network
> policies and, where possible, with Keycloak's `proxy-trusted-addresses`: the lookup ignores the header from
> untrusted proxies. The ZETA Guard Helm chart sets all of this up via `authserver.resourceServerMtls`.
