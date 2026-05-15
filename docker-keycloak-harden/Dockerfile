# Install updated libcap into a UBI Minimal stage (has microdnf; UBI Micro does not)
FROM registry.access.redhat.com/ubi9/ubi-minimal AS libcap-updater
RUN microdnf update -y libcap-2.48-10.el9_7.1 && microdnf clean all

# Install updated java-21-openjdk-headless into a UBI Minimal stage (has microdnf; UBI Micro does not)
FROM registry.access.redhat.com/ubi9/ubi-minimal AS openjdk-updater
RUN microdnf install -y java-21-openjdk-headless-21.0.11.0.10-2.el9 && microdnf clean all

FROM ${docker.image}

USER root
WORKDIR /opt/keycloak

# override io.netty.netty-codec, io.netty.netty-codec-dns, io.netty.netty-codec-http and io.netty.netty-codec-http2 because of
# CVE-2026-33870, CVE-2026-33871, CVE-2026-42583, CVE-2026-42579, CVE-2026-42584, CVE-2026-42587
# this can be deleted when these packages have been updated in the keycloak image
RUN rm lib/lib/main/io.netty.netty-codec-http-4.1.130.Final.jar && \
    rm lib/lib/main/io.netty.netty-codec-http2-4.1.130.Final.jar && \
    rm lib/lib/main/io.netty.netty-codec-4.1.130.Final.jar && \
    rm lib/lib/main/io.netty.netty-codec-dns-4.1.130.Final.jar

# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/netty-codec-http-4.1.133.Final.jar lib/lib/main/io.netty.netty-codec-http-4.1.130.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http2-4.1.133.Final.jar lib/lib/main/io.netty.netty-codec-http2-4.1.130.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-4.1.133.Final.jar lib/lib/main/io.netty.netty-codec-4.1.130.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-dns-4.1.133.Final.jar lib/lib/main/io.netty.netty-codec-dns-4.1.130.Final.jar

# overrides org.bouncycastle.bcpkix-jdk18on-1.82, org.bouncycastle.bcprov-jdk18on-1.82 and org.bouncycastle.bcutil-jdk18on-1.82
# because of CVE-2026-5598
# this can be deleted when these packages have been updated in the keycloak image to version >= 1.84
# This is a false negative: Trivy have not found this vulnerability
RUN rm bin/client/lib/bcprov-jdk18on-1.82.jar && \
    rm lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.82.jar && \
    rm lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.82.jar && \
    rm lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.82.jar
# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.84.jar bin/client/lib/bcprov-jdk18on-1.82.jar
COPY --chown=1000:1000 maven/jars/bcpkix-jdk18on-1.84.jar lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.82.jar
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.84.jar lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.82.jar
COPY --chown=1000:1000 maven/jars/bcutil-jdk18on-1.84.jar lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.82.jar

# override quarkus:quarkus-vertx-http because of CVE-2026-39852
# this can be deleted when these packages have been updated in the keycloak image
RUN rm lib/lib/main/io.quarkus.quarkus-vertx-http-3.27.3.jar
# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/quarkus-vertx-http-3.27.3.1.jar lib/lib/main/io.quarkus.quarkus-vertx-http-3.27.3.jar


# Update libcap to 2.48-10.el9_7.1 to fix CVEs (copied from ubi-minimal stage since UBI Micro has no package manager)
COPY --from=libcap-updater --chown=1000:1000 /usr/lib64/libcap.so.2* /usr/lib64/

# Update java-21-openjdk-headless to 1:21.0.11.0.10-2.el9 to fix CVEs (copied from ubi-minimal stage since UBI Micro has no package manager)
RUN rm -rf /usr/lib/jvm
RUN rm -rf /etc/alternatives
RUN rm -rf /etc/java

COPY --from=openjdk-updater --chown=1000:1000 /usr/lib/jvm/ /usr/lib/jvm/
COPY --from=openjdk-updater --chown=1000:1000 /etc/alternatives/ /etc/alternatives/
COPY --from=openjdk-updater --chown=1000:1000 /etc/java/ /etc/java/

USER keycloak
