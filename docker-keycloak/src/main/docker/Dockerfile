FROM ${docker.keycloak.image}:${keycloak.version} AS builder

# Keycloak build options, see https://www.keycloak.org/server/all-config?f=build
ENV KC_DB=postgres
ENV KC_HEALTH_ENABLED=true
ENV KC_METRICS_ENABLED=true

WORKDIR /opt/keycloak

COPY maven/providers/*.jar providers/

RUN /opt/keycloak/bin/kc.sh build

FROM ${docker.keycloak.image}:${keycloak.version}
COPY --from=builder /opt/keycloak/ /opt/keycloak/

USER root
ENV TZ=Europe/Berlin

# Set correct time zone
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

# Use BC provider as default security provider
COPY maven/java.security /etc/alternatives/jre/conf/security/

USER keycloak

ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
