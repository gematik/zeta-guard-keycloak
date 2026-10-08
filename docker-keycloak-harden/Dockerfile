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

# version must not be changed in the file name
COPY --chown=1000:1000 maven/jars/netty-codec-4.1.136.Final.jar                   lib/lib/main/io.netty.netty-codec-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-dns-4.1.136.Final.jar               lib/lib/main/io.netty.netty-codec-dns-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-haproxy-4.1.136.Final.jar           lib/lib/main/io.netty.netty-codec-haproxy-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http2-4.1.136.Final.jar             lib/lib/main/io.netty.netty-codec-http2-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-codec-http-4.1.136.Final.jar              lib/lib/main/io.netty.netty-codec-http-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-handler-4.1.136.Final.jar                 lib/lib/main/io.netty.netty-handler-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-resolver-dns-4.1.136.Final.jar            lib/lib/main/io.netty.netty-resolver-dns-4.1.135.Final.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.136.Final.jar  lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-aarch_64.jar
COPY --chown=1000:1000 maven/jars/netty-transport-native-epoll-4.1.136.Final.jar  lib/lib/main/io.netty.netty-transport-native-epoll-4.1.135.Final-linux-x86_64.jar

COPY --chown=1000:1000 maven/jars/bcpkix-jdk18on-1.85.jar                         lib/lib/main/org.bouncycastle.bcpkix-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.85.jar                         lib/lib/main/org.bouncycastle.bcprov-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcutil-jdk18on-1.85.jar                         lib/lib/main/org.bouncycastle.bcutil-jdk18on-1.84.jar
COPY --chown=1000:1000 maven/jars/bcprov-jdk18on-1.85.jar                         bin/client/lib/bcprov-jdk18on-1.84.jar

USER keycloak
