# Single source of the hardened feature set, see docs/internal/Erklärungen/Keycloak_hardening.md
ARG HARDENED_FEATURES_DISABLED=account,account-api,ciba,device-flow,jwt-authorization-grant,authorization,admin-fine-grained-authz,impersonation,workflows,identity-brokering-api

FROM ${docker.keycloak.image}:${keycloak.version} AS builder
ARG HARDENED_FEATURES_DISABLED

# Keycloak build options, see https://www.keycloak.org/server/all-config?f=build
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

# Disable Keycloak's own client registration endpoints, only 𝝵-Guard DCR (/clients-registrations/openid-connect) is supported.
# Build-time option, also needed in the runtime stage since startup.sh re-runs kc.sh build
ENV KC_SPI_CLIENT_REGISTRATION__DEFAULT__ENABLED=false
ENV KC_SPI_CLIENT_REGISTRATION__INSTALL__ENABLED=false
ENV KC_SPI_CLIENT_REGISTRATION__SAML2_ENTITY_DESCRIPTOR__ENABLED=false
ENV KC_SPI_WELL_KNOWN__UMA2_CONFIGURATION__ENABLED=false
# Keycloak's standard token exchange would serve every exchange the 𝝵-Guard providers decline, bypassing their checks
ENV KC_SPI_OAUTH2_TOKEN_EXCHANGE__STANDARD__ENABLED=false
ENV KC_FEATURES_DISABLED=$HARDENED_FEATURES_DISABLED

WORKDIR /opt/keycloak

# Provide default certificates for TPM-based authentication
COPY maven/ms-tpm-certificates.p12 conf/
COPY maven/*.yml conf/
# Quarkus build-time settings (parent-first BC to avoid split-classloader collision with bootstrap BC)
COPY maven/quarkus.properties conf/
COPY maven/startup.sh bin/
COPY maven/providers/*.jar providers/

# Effectively an optional COPY through wildcard and activated maven profile
COPY maven/${async.profiler}-* /opt/keycloak/${async.profiler}

# Disable Keycloak's own client registration endpoints, only 𝝵-Guard DCR (/clients-registrations/openid-connect) is supported.
# Build-time option, also needed in the runtime stage since startup.sh re-runs kc.sh build
ENV KC_SPI_CLIENT_REGISTRATION__DEFAULT__ENABLED=false
ENV KC_SPI_CLIENT_REGISTRATION__INSTALL__ENABLED=false
ENV KC_SPI_CLIENT_REGISTRATION__SAML2_ENTITY_DESCRIPTOR__ENABLED=false

RUN /opt/keycloak/bin/kc.sh build

# Keycloak runtime
FROM ${docker.keycloak.image}:${keycloak.version}
# ENV of the builder stage does not carry over, startup.sh needs the hardened set at runtime
ARG HARDENED_FEATURES_DISABLED
ENV KC_HARDENED_FEATURES_DISABLED=$HARDENED_FEATURES_DISABLED
COPY --from=builder --chown=1000:1000 /opt/keycloak/ /opt/keycloak/

USER root
RUN chown -R 1000:1000 /opt/keycloak && chmod -R g=u /opt/keycloak && chmod 755 /opt/keycloak/bin/*.sh /opt/keycloak/${async.profiler}/bin/*

ENV TZ=Europe/Berlin

# Set correct time zone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Use BC provider as default security provider
COPY maven/java.security /etc/alternatives/jre/conf/security/

USER keycloak

ENTRYPOINT ["/opt/keycloak/bin/startup.sh"]
