#!/usr/bin/env bash

echo "Running startup script"

# ── HSM keystore properties ───────────────────────────────────────────────────
# When HSM_PROXY_ENDPOINT and HSM_PROXY_KEY_ID are set, generate the HSMPROXY
# KeyStore properties file so KC_HTTPS_KEY_STORE_FILE can point to it.
# This keeps TLS configuration purely env-var driven — no mounted files needed.
if [[ -n "${HSM_PROXY_ENDPOINT}" && -n "${HSM_PROXY_KEY_ID}" ]]; then
  HSM_KEYSTORE_FILE="${HSM_KEYSTORE_FILE:-/opt/keycloak/conf/hsm-keystore.properties}"
  HSM_KEY_ALIAS="${HSM_KEY_ALIAS:-tls}"
  echo "🔐 Generating HSM keystore properties: ${HSM_KEYSTORE_FILE} (alias=${HSM_KEY_ALIAS})"
  cat >"${HSM_KEYSTORE_FILE}" <<EOF
hsm.endpoint=${HSM_PROXY_ENDPOINT}
keys.${HSM_KEY_ALIAS}.key_id=${HSM_PROXY_KEY_ID}
EOF
  echo "🔐 Generated HSM keystore properties: ${HSM_KEYSTORE_FILE}"$'\n'"$(cat "${HSM_KEYSTORE_FILE}")"
else
  echo "⚠️️ HSM proxy not configured — skipping HSM keystore properties (authserver.hsm.enabled=false)"
fi

# Keycloak integrity provider must be enabled explicitely, otherwise it is deleted from the container
if [ "${SPREE_INTEGRITY_PROVIDER_ENABLED}" != "true" ]; then
  echo "⚠️ Spree encryption provider disabled"
  echo "⚠️ Spree integrity provider disabled"

  # See dependencies of docker-keycloak/pom.xml
  # Among other reasons, the deletion prevents the creation of the checksum tables in the database
  rm -fv /opt/keycloak/providers/spree-encryption-provider.jar
else
  echo "🔐 Spree encryption provider enabled"

  if [ "${SPREE_ENABLE_INTEGRITY_CHECK}" != "true" ]; then
    echo "⚠️ Spree integrity checks disabled"
  else
    echo "🛡️ Spree integrity checks enabled"
  fi

  if [[ -n "${SPREE_KEYCHAIN_FILE}" && -f "${SPREE_KEYCHAIN_FILE}" ]]; then
    echo "☑️ SPREE_KEYCHAIN_FILE is set and the file exists."
  else
    echo "⚠️ SPREE_KEYCHAIN_FILE is not set or the file does not exist. Assuming keychain data is set directly via environment variables."
  fi
fi

# ── TLS named groups ─────────────────────────────────────────────────────────
# gemSpec_Krypt permits only P-256/P-384 for TLS 1.3 (brainpool groups exist in RFC 8734
# but not in the JDK). Also keeps X25519/X448 out — BC's BCXDHPublicKey doesn't implement
# JDK's java.security.interfaces.XECPublicKey, so with BC as provider #1 the JDK TLS
# engine throws ClassCastException during key-share generation.
export JAVA_OPTS_APPEND="-Djdk.tls.namedGroups=secp256r1,secp384r1 ${JAVA_OPTS_APPEND:-}"

# ── JCA providers on bootstrap classpath ─────────────────────────────────────
# JVM Security init resolves `security.provider.N=…` against the system classloader, which only sees what `-Xbootclasspath/a` exposes
# (lib/lib/main/ and providers/ come later via Quarkus). Without this:
#   - HSMPROXY: Quarkus 3.33's TLS Registry crashes with "HSMPROXY not found" before any KeyProviderFactory.postInit() runs.
#   - BC: BC registers late (post-bootstrap), so KeyStore.getInstance("PKCS12") returns SUN PKCS12 during Vert.x's SNI re-pack,
#     which triggers an encrypt/decrypt round-trip that fails on HsmEcPrivateKey ("extra data at the end").
HSM_PROXY_JAR="/opt/keycloak/providers/zeta-hsm-proxy-provider.jar"
KOTLIN_STDLIB_JAR=$(ls /opt/keycloak/providers/kotlin-stdlib-*.jar 2>/dev/null | head -1)
KOTLIN_REFLECT_JAR=$(ls /opt/keycloak/providers/kotlin-reflect-*.jar 2>/dev/null | head -1)
BC_JAR=$(ls /opt/keycloak/lib/lib/main/org.bouncycastle.bcprov-jdk18on-*.jar 2>/dev/null | head -1)

if [[ -f "${HSM_PROXY_JAR}" && -f "${KOTLIN_STDLIB_JAR}" && -f "${KOTLIN_REFLECT_JAR}" && -f "${BC_JAR}" ]]; then
  BOOTCP="${HSM_PROXY_JAR}:${KOTLIN_STDLIB_JAR}:${KOTLIN_REFLECT_JAR}:${BC_JAR}"
  export JAVA_OPTS_APPEND="-Xbootclasspath/a:${BOOTCP} ${JAVA_OPTS_APPEND:-}"
  echo "🔐 Bootstrap classpath additions: ${BOOTCP}"
else
  echo "⚠️  JCA providers not bootstrapped — required JAR(s) missing:"
  [[ ! -f "${HSM_PROXY_JAR}" ]] && echo "    - ${HSM_PROXY_JAR}"
  [[ -z "${KOTLIN_STDLIB_JAR}" ]] && echo "    - kotlin-stdlib-*.jar"
  [[ -z "${KOTLIN_REFLECT_JAR}" ]] && echo "    - kotlin-reflect-*.jar"
  [[ -z "${BC_JAR}" ]] && echo "    - org.bouncycastle.bcprov-jdk18on-*.jar (in /opt/keycloak/lib/lib/main/)"
fi

# shellcheck disable=SC2164
cd /opt/keycloak/bin

KC_DEBUG=false ./kc.sh build

rm -f /opt/keycloak/data/*.jfr

exec ./kc.sh "$@"
