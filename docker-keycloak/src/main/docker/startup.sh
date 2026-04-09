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
  cat > "${HSM_KEYSTORE_FILE}" <<EOF
hsm.endpoint=${HSM_PROXY_ENDPOINT}
keys.${HSM_KEY_ALIAS}.key_id=${HSM_PROXY_KEY_ID}
EOF
  echo "🔐 Generated HSM keystore properties: ${HSM_KEYSTORE_FILE}"$'\n'"$(cat "${HSM_KEYSTORE_FILE}")"
fi

# shellcheck disable=SC2164
cd /opt/keycloak/bin

./kc.sh build

rm -f /opt/keycloak/data/*.jfr

exec ./kc.sh "$@"
