# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

The project implements 𝝵-Guard, the authorization server (PDP) of gematik's ZETA specification as defined in https://gemspec.gematik.de/prereleases/Draft_ZETA_26_2/gemSpec_ZETA_V2.0.0_CC/.

- The programming language is Kotlin
- The project extends the Keycloak Docker image with various plugins, flows, REST endpoints and other extensions 
- The build environment is a Maven multi-module build, using JDK 21
- The targeted CI/CD environment is GitLab

Prerequisite: `plugins/hsm-proxy-provider` depends on `java-hsm-proxy-provider`, which is not on Maven Central — clone
`gematik/zeta-guard-java-hsm-proxy-provider`. It also depends on the Spree integrity provider (SIP) found in the keycloak-integrity-provider project.

## Commands

```shell
./mvnw clean install                                   # build all modules + unit tests + Keycloak Docker image
./mvnw clean install -P integration-tests              # additionally run runtime/integration-tests (*IT.kt) via Testcontainers
./mvnw clean install -P coverage,integration-tests     # JaCoCo aggregate report (aggregate-code-coverage)
./mvnw clean install -P profiling,integration-tests    # JFR profiling data

./mvnw -pl plugins/client-registration -am test -Dtest=ZetaGuardClientRegistrationPolicyTest   # single unit test class

./mvnw -Dspotless.skip=false -Dktfmt.skip=false generate-sources   # license-header check + ktfmt formatting
```

- Spotless (license headers) and ktfmt are **skipped by default** in local builds; ~~CI enables them~~ (temporarily disabled in CI too). Every
  `src/{main,test}/kotlin/**/*.kt` needs the Apache license header (`(C) tech@Spree GmbH, 2026, licensed for gematik GmbH`, `#%L` markers) — copy
  it from an existing file.
- Formatting: ~~ktfmt `KOTLINLANG` style, max width 150, block indent 2~~ ktfmt is temporarily disabled; we use IntelliJ's default Kotlin style +
  `.editorconfig` atm (no wildcard imports). Don't run `spotless:apply`/ktfmt over the code, it reformats most of the project.
- CI (`.gitlab-ci.yml`) runs `mvn -P coverage,integration-tests,gitlab,sbom,no-profiling verify`; SonarQube is the quality gate.

### Local stack and integration tests

- Test framework is **Kotest** (`FunSpec`) + MockK + kotest-assertions-arrow; JUnit Jupiter/JUnit 4 are excluded on purpose (engine conflicts).
  Unit tests are `*Test.kt` inside each module; `*IT.kt` exist only in `runtime/integration-tests`. Test clients/token generators
  (`KeycloakWebClient`, `KeycloakAdminClient`, `DPoPTokenGenerator`, `SMCBTokenGenerator`, `ClientAttestationGenerator`) live in `commons-client`.

## Architecture

- `commons-server`: shared server code — `KeycloakError`/`Outcomes.kt`, posture models (`ApplePosture`, `AndroidPosture`, `TPMPosture`,
  `SoftwarePosture`, `ClientStatementData`), OCSP/TPM/attestation utilities, keystores, OPA client pieces, constants (`Constants.kt`).
- `plugins/*`: one Keycloak extension area per module, each registering factories in
  `src/main/resources/META-INF/services/<Keycloak SPI interface FQN>`.
- `docker-keycloak`: `maven-dependency-plugin` copies every plugin jar (as `zeta-*.jar`) **and their runtime libraries** (kotlin-stdlib,
  arrow, jackson-kotlin, webauthn4j, …) into `providers/`; the Dockerfile runs `kc.sh build`. `docker-keycloak-harden` (profile `harden`)
  re-layers the image and strips vulnerable libraries.

**Adding a plugin module** requires: `<module>` in root `pom.xml`, SPI service files, an `artifactItem` (plus any new runtime dependency jars)
in `docker-keycloak/pom.xml`, an entry in `aggregate-code-coverage/pom.xml`, and if needed a provisioning script and env-var docs. Forgetting the
`docker-keycloak` step means the plugin compiles and unit-tests fine but is absent from the image.

### Main flows

- **Client registration (DCR)** — `plugins/client-registration`: `ZetaGuardClientRegistrationPolicy` dispatches on the parsed registration
  request type (`AppleRegistrationRequest` → `AppleAttestationChecker`, Android/software attestation). After registration, client data is
  persisted via JPA (`ZetaGuardDataService`, Liquibase changelogs tracked in table `databasechangelog_zeta_guard`), the mobile browser flow is
  bound, and optional mobile scopes are assigned. An expiration job removes stale clients/users.
- **Nonce** — `plugins/nonce-management`: `GET .../nonce` issues single-use nonces from an in-memory TTL cache, consumed by token exchange
  and attestation checks.
- **Token exchange (SMC-B)** — `plugins/smc-b-token-exchange` `ZetaGuardTokenExchangeProvider.tokenExchange()`: a chain of checks
  (integrity provider → x5c → grant type → subject token → certificate/OCSP → nonce → subject → key consistency → DPoP/key binding →
  client statement posture → OPA policy) before issuing the token.
- **OPA** — `OpaGateEnforcer` (Skip/Allow/Deny/Error) is shared by token exchange, `MobileOpaGate` (mobile authorization code) and the
  refresh-token grant. Policies/bundles for local runs are in `runtime/opa/`; the access-token TTL is decided by the policy.
- **SekIDP / OIDC flow** — `plugins/sekidp`: federation identity provider (`idp_iss` per request, trust chain via Federation Master), entity
  statement at `.well-known/openid-federation`, `zeta-outer-par` client policy executor, direct-redirect authenticator; together with
  `plugins/mobile-authorization-endpoint` (custom OIDC login protocol). Gated by `ZETA_OIDC_FLOW_ENABLED`.
- **Revocation** — `plugins/revocation`: report endpoint + SSE block list backed by Infinispan cache `zetaGuardRevocations`; requires the
  `zeta-guard-revocation-events` realm event listener.

### Realm provisioning and configuration

- `keycloak-config-cli` imports `runtime/realms/*.json` and then runs numbered shell scripts. `runtime/scripts-local/`, `scripts-prod/` and
  `runtime/integration-tests/scripts-it/` mostly contain **symlinks** into `runtime/scripts-repository/` — edit the target there and add a
  symlink in each environment that needs it.
- Environment variables are documented in `docs/references/Environment_variables.md`; security events/telemetry in
  `docs/references/Telemetry.md`. Keep both in sync when adding config or events.

## Conventions

- Error handling uses Arrow: `either { … }`, `ensure(cond) { KeycloakError(<OAuth error>, "message", <HTTP status>) }`, `.bind()`,
  `Either.catch {}.mapLeft {}`. Follow this rather than throwing.
- Logging via JBoss `Logger`; values in messages are quoted with `»…«`.
- User-facing changes go into `ReleaseNotes.md` under the `## Release TODO` section (`### added:` / `### changed:`), marking incompatible
  changes with `**BREAKING**`.

## Claude directives

- Do not reformat or change any code unless required by the current refactoring
- Update the release notes according to the current feature or refactoring
