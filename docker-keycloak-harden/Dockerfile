# patched OpenJDK 21 (>= 21.0.13.1) because of CVE-2026-114938 ("java4shell", heap out-of-bounds
# write in the AVX-512 Base64 decoder of HotSpot on x86-64, RHSB-2026-018) and others. The Keycloak image
# ships java-21-openjdk 21.0.11 and has no package manager, so the JVM is taken from this stage.
ARG JDK_VERSION=21.0.13.1.2-1.2.el9

FROM ${docker.image} AS base

FROM ${docker.jdk.image} AS jdk
ARG JDK_VERSION

RUN microdnf -y --nodocs install java-21-openjdk-headless-$JDK_VERSION \
 && microdnf clean all \
 && java -version

# registers the new JDK in the rpm database of the Keycloak image, scanners read the JDK version from there
COPY --from=base /var/lib/rpm/ /rpmdb/

RUN cd /tmp \
 && microdnf download java-21-openjdk-headless-$JDK_VERSION \
 && rpm --dbpath /rpmdb -U --justdb --nodeps --noscripts --notriggers java-21-openjdk-headless-*.rpm \
 && rpm --dbpath /rpmdb -q java-21-openjdk-headless | grep -qF "$JDK_VERSION" \
 && rm -f /rpmdb/.rpm.lock java-21-openjdk-headless-*.rpm \
 && microdnf clean all


FROM ${docker.image}

USER root
WORKDIR /opt/keycloak

# overrides the JDK because of CVE-2026-114938 — see the jdk stage above. The whole JVM including
# its versioned configuration (/etc/java) and the alternatives links is replaced; ownership stays
# root:root so that the runtime user cannot modify the JVM.
RUN rm -rf /usr/lib/jvm /etc/alternatives /etc/java

COPY --from=jdk /usr/lib/jvm/ /usr/lib/jvm/
COPY --from=jdk /etc/alternatives/ /etc/alternatives/
COPY --from=jdk /etc/java/ /etc/java/
COPY --from=jdk /rpmdb/ /var/lib/rpm/

# the JVM configuration of the Keycloak image is dropped with /etc/java, so the ZETA java.security
# (BouncyCastle as default provider) is applied again here
COPY maven/java.security /etc/alternatives/jre/conf/security/

RUN set -eu; \
    java -version 2>&1 | grep -q "21\.0\.13\.1" \
      || { echo "ERROR: java reports $(java -version 2>&1 | head -1)" >&2; exit 1; }; \
    grep -q "^security.provider.1=BC$" /etc/alternatives/jre/conf/security/java.security \
      || { echo "ERROR: customized java.security is not in effect" >&2; exit 1; }; \
    keytool -list -cacerts -storepass changeit > /dev/null \
      || { echo "ERROR: cacerts is not readable" >&2; exit 1; }

# overrides netty dependencies because of several vulnerabilities
RUN rm lib/lib/main/io.netty.netty-codec-haproxy-4.1.133.Final.jar \
 && rm lib/lib/main/io.netty.netty-codec-http2-4.1.133.Final.jar \
 && rm lib/lib/main/io.netty.netty-handler-4.1.133.Final.jar \
 && rm lib/lib/main/io.netty.netty-resolver-dns-4.1.133.Final.jar \
 && rm lib/lib/main/io.netty.netty-transport-native-epoll-4.1.133.Final-linux-aarch_64.jar \
 && rm lib/lib/main/io.netty.netty-transport-native-epoll-4.1.133.Final-linux-x86_64.jar

# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/netty-codec-haproxy-4.1.135.Final.jar           lib/lib/main/io.netty.netty-codec-haproxy-4.1.133.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http2-4.1.135.Final.jar             lib/lib/main/io.netty.netty-codec-http2-4.1.133.Final.jar
COPY --chown=1000:1000 maven/jars/netty-handler-4.1.135.Final.jar                 lib/lib/main/io.netty.netty-handler-4.1.133.Final.jar
COPY --chown=1000:1000 maven/jars/netty-resolver-dns-4.1.135.Final.jar            lib/lib/main/io.netty.netty-resolver-dns-4.1.133.Final.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.135.Final.jar  lib/lib/main/io.netty.netty-transport-native-epoll-4.1.133.Final-linux-aarch_64.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.135.Final.jar  lib/lib/main/io.netty.netty-transport-native-epoll-4.1.133.Final-linux-x86_64.jar

USER keycloak
