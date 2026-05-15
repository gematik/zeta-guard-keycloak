# How to Configure HSM Token Signing via Admin UI

Step-by-step guide to enable HSM-backed ES256 token signing in Keycloak using only the
Admin Console. This assumes:

- Keycloak is deployed and healthy (`make deploy stage=<env>`)
- Terraform realm configuration has been applied (`make config stage=<env>`)
- HSM Proxy (or `hsm-sim`) is reachable from the authserver pods
- `HSM_PROXY_ENDPOINT` env var is set on the authserver (via Helm `authserver.hsm.enabled: true`)

---

## Step 1 — Log in to the Admin Console

Open `https://<hostname>/auth/admin` and log in with the admin credentials.

---

## Step 2 — Select the target realm

In the realm dropdown (top-left), select the realm you want to configure (e.g., **zeta-guard**).

> Repeat Steps 2–8 for master-realm if HSM token signing is required.

---

## Step 3 — Add the HSM token signing key provider

1. Go to **Realm Settings** → **Keys** → **Providers** tab
2. Click **Add provider**
3. Select **zeta-hsm-token-signing** from the dropdown
4. Fill in the configuration:

| Field                  | Value                                     | Description                                                                                           |
|------------------------|-------------------------------------------|-------------------------------------------------------------------------------------------------------|
| **Priority**           | `200`                                     | Must be higher than software keys (default 100) so the HSM key is selected for signing                |
| **HSM Proxy Endpoint** | `hsm-sim:50051`                           | gRPC address of the HSM Proxy. Use `hsm-sim:50051` for non-production, or the production HSM endpoint |
| **Key ID**             | `zeta-guard-keycloak-token-es256-v1.p256` | Identifier of the signing key in the HSM                                                              |

5. Click **Save**

---

## Step 4 — Verify the default signature algorithm is ES256

> **Note:** This is already configured by Terraform (`realm.tf`: `default_signature_algorithm = "ES256"`).
> If you ran `make config stage=<env>` before this step, the realm is already set to ES256. Verify it:

1. Go to **Realm Settings** → **Tokens** tab
2. Confirm **Default Signature Algorithm** is set to **ES256**
3. If it's not, change it to **ES256** and click **Save**

---

## Step 5 — Remove software signing keys (optional but recommended)

To ensure all tokens are signed exclusively by the HSM key (no software fallback):

1. Go to **Realm Settings** → **Keys** → **Providers** tab
2. Find and delete the following providers (click the **trash icon** on each row):
    - **rsa-generated** (RSA software signing key)
    - **ecdsa-generated** (EC software signing key, if present)
3. **Keep** the following providers — they are NOT signing keys:
    - **hmac-generated** (HMAC key for internal tokens)
    - **aes-generated** (AES key for encryption)
    - Any provider with `use: enc` (encryption keys)

---

## Step 6 — Verify the JWKS endpoint

```bash
curl -s https://<hostname>/auth/realms/zeta-guard/protocol/openid-connect/certs \
  | jq '.keys[] | select(.use == "sig") | {kid, alg}'
```

Expected output — only the HSM ES256 key for signing:

```json
{
  "kid": "<hsm-key-id>",
  "alg": "ES256"
}
```

If you see additional `RS256` or `ES256` signing keys, go back to Step 5 and remove
the remaining software providers.

---

## Step 7 — Verify token signing

Get a token (e.g., via the test-driver or token exchange) and decode the JWT header:

```bash
echo "<access_token>" | cut -d. -f1 | base64 -d 2>/dev/null | jq .
```

Expected:

```json
{
  "alg": "ES256",
  "typ": "JWT",
  "kid": "<hsm-key-id>"
}
```

The `kid` should match the HSM key from the JWKS endpoint (Step 6).

---

## Rollback

To disable HSM token signing and revert to software keys:

1. **Realm Settings** → **Keys** → **Providers** → delete **hsm-token-signing**
2. **Realm Settings** → **Tokens** → set **Default Signature Algorithm** back to `RS256`
3. Keycloak automatically generates new software signing keys on next token request

---

## Troubleshooting

| Symptom                                           | Cause                                                     | Fix                                                                     |
|---------------------------------------------------|-----------------------------------------------------------|-------------------------------------------------------------------------|
| `zeta-hsm-token-signing` not in provider dropdown | Plugin JAR not deployed                                   | Verify version of keycloal-zeta (and release-notes)                     |
| Save fails with "HSM endpoint not configured"     | Empty endpoint field                                      | Enter the gRPC address (e.g., `hsm-sim:50051`)                          |
| Token still uses RS256 after config               | `defaultSignatureAlgorithm` not changed                   | Go to Tokens tab and set to ES256 (Step 4)                              |
| Token uses ES256 but wrong `kid`                  | Software EC key has higher priority or HSM key not active | Check provider priorities in Keys → Providers; HSM should be 200        |
| JWKS shows no signing keys                        | All providers deleted                                     | Keycloak auto-generates a fallback; add the HSM provider again (Step 3) |
| `Connection refused` in logs                      | HSM Proxy not reachable                                   | Verify `hsm-sim` pod is running and endpoint is correct                 |
