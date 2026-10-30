FROM ${docker.image}

USER root
WORKDIR /opt/keycloak

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
