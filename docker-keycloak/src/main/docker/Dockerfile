FROM ${docker.keycloak.image}:${keycloak.version} AS builder

# Keycloak build options, see https://www.keycloak.org/server/all-config?f=build
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

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

RUN /opt/keycloak/bin/kc.sh build

# Keycloak runtime
FROM ${docker.keycloak.image}:${keycloak.version}
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
