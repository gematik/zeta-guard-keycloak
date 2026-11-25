# Environment variables

In addition to Keycloak's standard environment variables, the following environment variables are supported:

## Required environment variables

| Name | Description |
|------|-------------|

## Optional environment variables

| Name                                        | Default value       | Description                                                                                                                                                                                                                        |
|---------------------------------------------|---------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `GENESIS_HASH`                              | random              | The seed used instead of a previous hash to calculate the first hash in the admin event log. A random string of up to 64 characters.                                                                                               |
| `TRUSTSTORE_RELOAD_ENABLED`                 | `true`              | Whether the SMC-B, TPM and OCSP truststores are reloaded while the server runs. `false` reads them only at startup.                                                                                                                |
| `TRUSTSTORE_RELOAD_INTERVAL`                | `PT1H`              | How often the truststores are checked for changes, as an ISO-8601 duration of hours or less.                                                                                                                                       |
| `CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE` | `500`               | Maximum number of expired client registrations, clients and users the expiration job removes per run (each run is one transaction). A larger backlog (e.g. after a load test) is worked off over several runs, see the note below. |
| `ENTITY_STATEMENT_CLIENT_NAME`              | `zeta-guard`        | Name of the ZETA Guard in the OpenID-Federation entity statement: `metadata.openid_relying_party.client_name` and `metadata.federation_entity.name`.                                                                               |
| `ENTITY_STATEMENT_ORGANIZATION_NAME`        | `zeta-guard`        | Operating organization in the entity statement: `organization_name` in `metadata.openid_relying_party` and `metadata.federation_entity`.                                                                                           |
| `ENTITY_STATEMENT_CONTACT_EMAIL`            | `noreply@localhost` | Contact address in `metadata.openid_relying_party.contacts` of the entity statement.                                                                                                                                               |
| `ENTITY_STATEMENT_ID_TOKEN_VERSION`         | `1.0.0`             | ID token version announced in `metadata.openid_relying_party.ti_features_supported.id_token_version_supported`.                                                                                                                    |
| `ENTITY_STATEMENT_REDIRECT_URIS`            | unset               | Comma-separated list published as `metadata.openid_relying_party.redirect_uris` in the entity statement. Unset or blank, the redirect URIs of all clients in the realm are published.                                              |

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

The truststores named by `SMCB_KEYSTORE_LOCATION`, `TPM_KEYSTORE_LOCATION` and `OCSP_KEYSTORE_LOCATION`, together with
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
