FROM ${docker.image}

USER root
WORKDIR /opt/keycloak

# overrides netty dependencies because of several vulnerabilities
RUN rm lib/lib/main/io.netty.netty-codec-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-codec-dns-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-codec-haproxy-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-codec-http2-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-codec-http-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-handler-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-resolver-dns-4.1.135.Final.jar \
 && rm lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-aarch_64.jar \
 && rm lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-x86_64.jar

# overrides bouncycastle dependencies because of several vulnerabilities
RUN rm lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.84.jar \
 && rm lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.84.jar \
 && rm lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.84.jar \
 && rm bin/client/lib/bcprov-jdk18on-1.84.jar

# overrides mariadb jdbc driver because of several vulnerabilities
RUN rm lib/lib/main/org.mariadb.jdbc.mariadb-java-client-3.5.7.jar

# overrides jackson dependencies because of several vulnerabilities
RUN rm lib/lib/main/com.fasterxml.jackson.core.jackson-core-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.dataformat.jackson-dataformat-cbor-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.dataformat.jackson-dataformat-yaml-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.datatype.jackson-datatype-jdk8-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.datatype.jackson-datatype-jsr310-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.jakarta.rs.jackson-jakarta-rs-base-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.jakarta.rs.jackson-jakarta-rs-yaml-provider-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.module.jackson-module-jakarta-xmlbind-annotations-2.21.2.jar \
 && rm lib/lib/main/com.fasterxml.jackson.module.jackson-module-parameter-names-2.21.2.jar

# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/netty-codec-4.1.139.Final.jar                                     lib/lib/main/io.netty.netty-codec-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-dns-4.1.139.Final.jar                                 lib/lib/main/io.netty.netty-codec-dns-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-haproxy-4.1.139.Final.jar                             lib/lib/main/io.netty.netty-codec-haproxy-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http2-4.1.139.Final.jar                               lib/lib/main/io.netty.netty-codec-http2-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http-4.1.139.Final.jar                                lib/lib/main/io.netty.netty-codec-http-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-handler-4.1.139.Final.jar                                   lib/lib/main/io.netty.netty-handler-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-resolver-dns-4.1.139.Final.jar                              lib/lib/main/io.netty.netty-resolver-dns-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.139.Final-linux-aarch_64.jar     lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-aarch_64.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.139.Final-linux-x86_64.jar       lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-x86_64.jar

COPY --chown=1000:1000 maven/jars/bcpkix-jdk18on-1.86.jar                                           lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.86.jar                                           lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcutil-jdk18on-1.86.jar                                           lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.86.jar                                           bin/client/lib/bcprov-jdk18on-1.84.jar

COPY --chown=1000:1000 maven/jars/mariadb-java-client-3.5.9.jar                   lib/lib/main/org.mariadb.jdbc.mariadb-java-client-3.5.7.jar
COPY --chown=1000:1000 maven/jars/jackson-core-2.21.7.jar                                lib/lib/main/com.fasterxml.jackson.core.jackson-core-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-databind-2.21.7.jar                            lib/lib/main/com.fasterxml.jackson.core.jackson-databind-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-dataformat-cbor-2.21.7.jar                     lib/lib/main/com.fasterxml.jackson.dataformat.jackson-dataformat-cbor-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-dataformat-yaml-2.21.7.jar                     lib/lib/main/com.fasterxml.jackson.dataformat.jackson-dataformat-yaml-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-datatype-jdk8-2.21.7.jar                       lib/lib/main/com.fasterxml.jackson.datatype.jackson-datatype-jdk8-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-datatype-jsr310-2.21.7.jar                     lib/lib/main/com.fasterxml.jackson.datatype.jackson-datatype-jsr310-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-jakarta-rs-base-2.21.7.jar                     lib/lib/main/com.fasterxml.jackson.jakarta.rs.jackson-jakarta-rs-base-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-jakarta-rs-yaml-provider-2.21.7.jar            lib/lib/main/com.fasterxml.jackson.jakarta.rs.jackson-jakarta-rs-yaml-provider-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-module-jakarta-xmlbind-annotations-2.21.7.jar  lib/lib/main/com.fasterxml.jackson.module.jackson-module-jakarta-xmlbind-annotations-2.21.2.jar
COPY --chown=1000:1000 maven/jars/jackson-module-parameter-names-2.21.7.jar              lib/lib/main/com.fasterxml.jackson.module.jackson-module-parameter-names-2.21.2.jar

# Remove the compromised emSign / eMudhra root CAs (eight emSign intermediate CA keys compromised,
# CVE-2026-114406 / CVE-2026-91403). A forged chain under these roots must not be trusted: for the
# Authserver a forged Federation Master / SekIDP would otherwise allow registering users with a
# freely chosen KVNR. Keycloak uses the JVM cacerts for outbound TLS (decisive); the OS trust
# bundles are cleaned too for defense in depth. update-ca-trust is unusable here (libp11-kit is
# absent in the base image), so both stores are edited directly.
RUN set -eu; \
    for alias in emsignrootca-c1 emsigneccrootca-c3 emsignrootca-g1 emsigneccrootca-g3; do \
      keytool -delete -cacerts -storepass changeit -alias "$alias" 2>/dev/null || true; \
    done; \
    for f in /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem \
             /etc/pki/ca-trust/extracted/pem/email-ca-bundle.pem \
             /etc/pki/ca-trust/extracted/pem/objsign-ca-bundle.pem \
             /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt; do \
      [ -f "$f" ] && sed -i '/^# emSign/,/^-----END.*CERTIFICATE-----/d' "$f"; \
    done; \
    ! keytool -list -cacerts -storepass changeit 2>/dev/null | grep -qi emsign \
      || { echo "ERROR: emSign roots still present in cacerts" >&2; exit 1; }; \
    ! grep -rqi emSign /etc/pki/ca-trust/extracted/pem/ \
                       /etc/pki/ca-trust/extracted/openssl/ca-bundle.trust.crt \
      || { echo "ERROR: emSign roots still present in OS trust bundles" >&2; exit 1; }


USER keycloak
