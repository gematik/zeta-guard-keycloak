# Telemetry reference

## Logs

### Event authn_authorization_code_invalid

**Description:** invalid authorization code received during
SMC-B token exchange

**Level:** INFO

**Endpoints:** POST
/realms/zeta-guard/protocol/openid-connect/token

**Properties:**

| Key                  | Requirement Level | Value Type | Description                                     | Example Values                     |
|----------------------|-------------------|------------|-------------------------------------------------|------------------------------------|
| `zeta-client.reason` | mandatory         | string     | Reason why the authorization code was rejected. |                                    |
| `event_type`         | mandatory         | string     | Security event type                             | `authn_authorization_code_invalid` |

### Event authn_client_deleted:clientId

**Description:** a client registration was deleted by ZETA Guard, e.g. the least-recently-used client of a user
because the maximum number of clients per user (`SMCB_USER_MAX_CLIENTS`) was exceeded by a new registration
(A_25748-02)

**Level:** INFO

**Endpoints:** POST /realms/zeta-guard/protocol/openid-connect/token

**Properties:**

| Key                  | Requirement Level | Value Type | Description                        | Example Values         |
|----------------------|-------------------|------------|------------------------------------|------------------------|
| `auth.client_id`     | mandatory         | string     | Client id of the deleted client    |                        |
| `zeta-client.reason` | mandatory         | string     | Reason why the client was deleted. | `max_clients_exceeded` |
| `event_type`         | mandatory         | string     | Security event type                | `authn_client_deleted` |

### Event authn_client_registered:clientId

**Description:** client registered successfully

**Level:** INFO

**Endpoints:** POST
/realms/zeta-guard/clients-registrations/openid-connect

**Properties:**

| Key              | Requirement Level | Value Type | Description         | Example Values            |
|------------------|-------------------|------------|---------------------|---------------------------|
| `auth.client_id` | mandatory         | string     | Client id           |                           |
| `event_type`     | mandatory         | string     | Security event type | `authn_client_registered` |

### Event authn_client_registration_fail

**Description:** client registration failed

**Level:** INFO

**Endpoints:**

- POST
  /realms/zeta-guard/clients-registrations/openid-connect
- POST /realms/zeta-guard/protocol/openid-connect/token

**Properties:**

| Key                  | Requirement Level | Value Type | Description                                      | Example Values                                                                          |
|----------------------|-------------------|------------|--------------------------------------------------|-----------------------------------------------------------------------------------------|
| `auth.client_id`     | mandatory         | string     | Client id                                        |                                                                                         |
| `zeta-client.reason` | mandatory         | string     | Reason why the client registration was rejected. | `integrity_provider_unavailable`, `registration_expired`, `too_many_clients_registered` |
| `event_type`         | mandatory         | string     | Security event type                              | `authn_client_registration_fail`                                                        |

### Event authn_email_change:clientId

**Description:** the e-mail address bound to an identity was replaced.

**Level:** INFO

**Endpoints:** POST /realms/zeta-guard/zeta/identity/email

**Properties:**

| Key              | Requirement Level | Value Type | Description                         | Example Values                         |
|------------------|-------------------|------------|-------------------------------------|----------------------------------------|
| `auth.client_id` | mandatory         | string     | Client id that performed the change | `13c32c3e-57e6-42c2-82f1-d8346fcc7ed1` |
| `event_type`     | mandatory         | string     | Security event type                 | `authn_email_change`                   |

### Event authn_token_created:clientId

**Description:** token exchange, usually after client
registration

**Level:** INFO

**Endpoints:** POST
/realms/zeta-guard/protocol/openid-connect/token

**Properties:**

| Key                                  | Requirement Level       | Value Type | Description                             | Example Values                |
|--------------------------------------|-------------------------|------------|-----------------------------------------|-------------------------------|
| `auth.client_id`                     | mandatory               | string     | Client id                               |                               |
| `client_registration.client.os.name` | conditionally mandatory | string     | Client operating system name            | `android`                     |
| `client_registration.datetime`       | mandatory               | int        | Timestamp of client registration        | `1784561340`                  |
| `client_registration.result`         | mandatory               | string     | Result of attempted client registration | `PENDING`, `VALID`, `INVALID` |
| `event_type`                         | mandatory               | string     | Security event type                     | `authn_token_created`         |

### Event "Possible attack detected"

**Description:** suspected attack detected

**Level:** WARN

**Endpoints:** any

**Properties:**

| Key                         |           | Value Type | Description         | Example Values                                                          |
|-----------------------------|-----------|------------|---------------------|-------------------------------------------------------------------------|
| `attackDetection.capecId`   | mandatory | int        | Attack Pattern ID   | `115`                                                                   |
| `attackDetection.capecName` | mandatory | string     | Attack Pattern Name | `"Authentication Bypass"`                                               |
| `attackDetection.clientIP`  | mandatory | string     |                     | `127.0.0.1`                                                             |
| `attackDetection.detail`    | mandatory | string     |                     | `Expected audience not available in the token`                          |
| `attackDetection.origin`    | optional  | string     |                     | `org.keycloak.TokenVerifier$AudienceCheck.test(TokenVerifier.java:163)` |

## Tracing

### Attack detection spans

#### Attributes

| Key                         |           | Value Type | Description         | Example Values                                                          |
|-----------------------------|-----------|------------|---------------------|-------------------------------------------------------------------------|
| `attackDetection.capecId`   | mandatory | int        | Attack Pattern ID   | `115`                                                                   |
| `attackDetection.capecName` | mandatory | string     | Attack Pattern Name | `"Authentication Bypass"`                                               |
| `attackDetection.clientIP`  | mandatory | string     |                     | `127.0.0.1`                                                             |
| `attackDetection.detail`    | mandatory | string     |                     | `Expected audience not available in the token`                          |
| `attackDetection.origin`    | optional  | string     |                     | `org.keycloak.TokenVerifier$AudienceCheck.test(TokenVerifier.java:163)` |

