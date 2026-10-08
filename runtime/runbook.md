# Local Runbook — zeta-guard Docker Compose

## Services

| Service               | Container                   | Description                                  |
|-----------------------|-----------------------------|----------------------------------------------|
| `keycloak`            | `zeta-guard-keycloak`       | Keycloak with zeta-guard plugins             |
| `keycloak-db`         | `zeta-guard-postgres`       | PostgreSQL 17 backing Keycloak               |
| `keycloak-config-cli` | `keycloak-config-cli`       | Imports realm configs and runs setup scripts |
| `opa`                 | `zeta-guard-opa`            | OPA policy engine (active bundle)            |
| `opa-simulation`      | `zeta-guard-opa-simulation` | OPA policy engine (simulation bundle)        |
| `lgtm`                | —                           | Grafana LGTM stack (logs, traces, metrics)   |
| `hsm-sim`             | `zeta-guard-hsm-sim`        | HSM simulator (gRPC, added by HSM overlay)   |

## Ports

| Port    | Service                    | Notes                                                        |
|---------|----------------------------|--------------------------------------------------------------|
| `18080` | Keycloak HTTP API          | `http://localhost:18080` — loopback only                     |
| `18443` | Keycloak HTTPS API         | `https://localhost:18443` — loopback only, TLS overlays only |
| `18787` | Keycloak JDWP debug        | loopback only                                                |
| `15432` | PostgreSQL                 | direct DB access                                             |
| `18181` | OPA API                    | active policy bundle                                         |
| `18282` | OPA diagnostics            | active policy bundle                                         |
| `18183` | OPA simulation API         | simulation bundle                                            |
| `18284` | OPA simulation diagnostics | simulation bundle                                            |
| `13000` | Grafana                    | `http://localhost:13000` — user: `admin`, password: `admin`  |
| `14317` | OpenTelemetry gRPC         |                                                              |
| `14318` | OpenTelemetry HTTP         |                                                              |

## Default credentials

| What                       | Value                   |
|----------------------------|-------------------------|
| Keycloak admin username    | `zeta`                  |
| Keycloak admin password    | `sigma`                 |
| PostgreSQL user / password | `zeta-guard` / `geheim` |
| Grafana                    | `admin` / `admin`       |

## Scenarios

All commands run from the `runtime/` directory.

### Scenario 1 — Plain (no TLS, no HSM)

```shell
docker compose up
```

### Scenario 2 — With HSM simulator (no TLS)

Registers the gRPC channel to `hsm-sim` at Keycloak startup.

```shell
docker compose -f compose.yaml -f overlays/compose.hsm.yaml up
```

### Scenario 3 — TLS from HSM

Key and certificate are fetched from `hsm-sim` via gRPC.
Requires the HSM overlay.

```shell
docker compose -f compose.yaml -f overlays/compose.hsm.yaml -f overlays/compose.tls-hsm.yaml up
```

Keycloak is available at `https://localhost:18443`.

### Scenario 4 — TLS from volume (no HSM)

PEM certificate and private key are mounted from
`conf/tls/`.

**Prerequisite — generate the certificate once:**

```shell
cd conf/tls && ./gen-cert.sh
```

```shell
docker compose -f compose.yaml -f overlays/compose.tls-volume.yaml up
```

Keycloak is available at `https://localhost:18443`.

### Scenario 5 — TLS from volume + HSM

```shell
cd conf/tls && ./gen-cert.sh  # once
docker compose -f compose.yaml -f overlays/compose.hsm.yaml -f overlays/compose.tls-volume.yaml up
```

### Scenario 6 — HSM token signing (no TLS)

JWT tokens are signed with a key held in `hsm-sim`.
`keycloak-config-cli` registers the HSM KeyProvider and
removes software signing keys.

```shell
docker compose -f compose.yaml -f overlays/compose.hsm.yaml -f overlays/compose.token-signing-hsm.yaml up
```

### Scenario 7 — HSM token signing + TLS from HSM

```shell
docker compose -f compose.yaml -f overlays/compose.hsm.yaml -f overlays/compose.tls-hsm.yaml -f overlays/compose.token-signing-hsm.yaml up
```

### Scenario 8 — Observability (logs and tracing)

Starts an OpenTelemetry backend and enables OpenTelemetry
log export and distributed tracing for Keycloak and OPA –
excluding OPA simulator.

```shell
docker compose -f compose.yaml -f overlays/compose.hsm.yaml -f overlays/compose.observability.yaml up
```

Visit Grafana at `http://localhost:13000`.

### Scenario 9 — CPU profiling (async-profiler)

Uses a separate base file that starts Keycloak with
async-profiler attached.
Writes a JFR file to `../target/zeta-guard.jfr` on container
stop.

```shell
docker compose -f compose-profiling.yaml up
```

Stop the stack to flush the profiler output (grace period:
30 s):

```shell
docker compose -f compose-profiling.yaml down
```

Open the `.jfr` file with IntelliJ, JDK Mission Control, or
async-profiler's converter.

## Environment variables

Override these on the shell before running
`docker compose up`:

| Variable                             | Default                                    | Description                                                                       |
|--------------------------------------|--------------------------------------------|-----------------------------------------------------------------------------------|
| `KC_DEBUG_SUSPEND`                   | `n`                                        | Set to `y` to suspend Keycloak on startup until a debugger connects on port 18787 |
| `GENESIS_HASH`                       | (see compose.yaml)                         | Initial hash for the admin-events integrity chain                                 |
| `SMCB_HASHING_PEPPER`                | (see compose.yaml)                         | Pepper for SMC-B certificate hashing                                              |
| `SPREE_INTEGRITY_PROVIDER_ENABLED`   | `false`                                    | Enable Spree integrity provider, the other configurations depend on this value    |
| `SPREE_ENABLE_INTEGRITY_CHECK`       | `false`                                    | Enable integrity checks                                                           |
| `SPREE_ENABLE_INTEGRITY_ROW_CHECK`   | `true`                                     | Enable row-wise integrity checks                                                  |
| `SPREE_ENABLE_INTEGRITY_TABLE_CHECK` | `false`                                    | Enable integrity checks per table/entity                                          |
| `SPREE_ENABLE_COLUMN_ENCRYPTION`     | `true`                                     | Enable column encryption                                                          |
| `IMAGE_KEYCLOAK_CONFIG`              | `zeta/zeta-guard/keycloak-config-cli`      | Override the config-cli image                                                     |
| `HSM_SIM_IMAGE` / `HSM_SIM_TAG`      | `zeta/zeta-guard/ngx_pep/hsm_sim` / `main` | HSM simulator image                                                               |

## Overlay composition reference

```
compose.yaml                                        # base — always required
  └─ overlays/compose.hsm.yaml                      # adds hsm-sim; required by tls-hsm and token-signing-hsm
       └─ overlays/compose.tls-hsm.yaml             # TLS via HSM gRPC
       └─ overlays/compose.token-signing-hsm.yaml   # JWT signing via HSM
  └─ overlays/compose.tls-volume.yaml               # TLS via PEM files in conf/tls/
  └─ overlays/compose.observability.yaml            # OPA distributed tracing + explicit LGTM
```

## Debug logging

Append to the `keycloak` service `command:` in
`compose.yaml` to enable SQL or Keycloak DEBUG logs:

```
--log-level=org.keycloak:DEBUG
--log-level=org.hibernate.SQL:DEBUG
```
