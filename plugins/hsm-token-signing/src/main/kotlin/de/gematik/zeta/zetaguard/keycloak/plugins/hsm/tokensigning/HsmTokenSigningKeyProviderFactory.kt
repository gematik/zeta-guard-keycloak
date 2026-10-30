/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) tech@Spree GmbH, 2026, licensed for gematik GmbH
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * *******
 *
 * For additional notes and disclaimer from gematik and in case of changes by gematik find details in the "Readme" file.
 * #L%
 */
package de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning

import de.gematik.zetaguard.hsmproxy.HsmProxyProvider
import java.io.ByteArrayOutputStream
import java.security.KeyStore
import java.util.Properties
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.crypto.KeyUse
import org.keycloak.keys.KeyProvider
import org.keycloak.keys.KeyProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(HsmTokenSigningKeyProviderFactory::class.java)

/** KeyStore alias used when loading the token-signing key from HsmKeyStoreSpi. */
internal const val TOKEN_KEY_ALIAS = "token"

/**
 * [KeyProviderFactory] for HSM-backed ES256 token signing.
 *
 * Component config (`endpoint`, `keyId`, `priority`) is registered per-realm by the admin (Admin UI / `kcadm.sh` / Terraform) — the plugin does not
 * self-register. The JCA `HsmProxyProvider` is registered by the JVM at init via `security.provider.2=HSMPROXY` in `conf/security/java.security`,
 * resolved against `-Xbootclasspath/a:` set up in `docker-keycloak/src/main/docker/startup.sh`.
 */
open class HsmTokenSigningKeyProviderFactory : KeyProviderFactory<HsmTokenSigningKeyProvider> {

  @Volatile private var cachedKeyStore: KeyStore? = null

  // Fail-closed gate (env: KC_SPI_KEYS_ZETA_HSM_TOKEN_SIGNING_FAIL_CLOSED), default true.
  @Volatile internal var failClosed: Boolean = true

  override fun getId() = PROVIDER_ID

  override fun init(config: Config.Scope) {
    failClosed = config.getBoolean(CONFIG_FAIL_CLOSED, true)
    log.info("🔐 HSM token signing fallback guard: failClosed={}", failClosed)
  }

  override fun create(session: KeycloakSession, model: ComponentModel): HsmTokenSigningKeyProvider {
    val ks =
        cachedKeyStore
            ?: synchronized(this) {
              cachedKeyStore
                  ?: buildKeyStore(
                          model[CONFIG_ENDPOINT] ?: throw RuntimeException("HSM endpoint not configured"),
                          model[CONFIG_KEY_ID] ?: throw RuntimeException("HSM keyId not configured"),
                      )
                      .also { cachedKeyStore = it }
            }
    return HsmTokenSigningKeyProvider(model) { _, _ -> ks }
  }

  override fun getHelpText() = "HSM-backed EC key for JWT token signing via HSM Proxy gRPC"

  override fun getConfigProperties(): List<ProviderConfigProperty> = CONFIG_PROPERTIES

  override fun close() = Unit

  /** Fail-closed guard: refuses software signing-key fallback for HSM-enforcing realms. Non-SIG uses pass through. */
  override fun createFallbackKeys(session: KeycloakSession, keyUse: KeyUse, algorithm: String): Boolean {
    if (!failClosed) return false
    if (keyUse != KeyUse.SIG) return false

    // Realms without the provider component (e.g. master at first boot) fall through, otherwise admin auth deadlocks the tooling that provisions HSM
    // keys.
    val realmName = hsmEnforcingRealmName(session) ?: return false

    log.error(
        "🔐 HSM token signing required (failClosed=true) but no active {} signing key is available for realm='{}'. " +
            "Refusing to generate a software fallback key. Token issuance will fail until the HSM is reachable.",
        algorithm,
        realmName,
    )
    throw HsmUnavailableException(
        "HSM token signing required but no active HSM-backed $algorithm signing key is available (realm=$realmName). " +
            "Software fallback is disabled by policy."
    )
  }

  /** Returns the realm name if it has our key-provider component, else null. Test seam: mockk can't proxy KeycloakContext on this classpath. */
  internal open fun hsmEnforcingRealmName(session: KeycloakSession): String? {
    val realm = session.context?.realm ?: return null
    val usesHsm = realm.getComponentsStream(realm.id, KeyProvider::class.java.name).anyMatch { it.providerId == PROVIDER_ID }
    return if (usesHsm) realm.name else null
  }

  internal open fun buildKeyStore(endpoint: String, keyId: String): KeyStore {
    val props =
        Properties().apply {
          setProperty("hsm.endpoint", endpoint)
          setProperty("keys.$TOKEN_KEY_ALIAS.key_id", keyId)
        }
    val baos = ByteArrayOutputStream()
    props.store(baos, null)
    return KeyStore.getInstance(HsmProxyProvider.KEYSTORE_TYPE).also { it.load(baos.toByteArray().inputStream(), null) }
  }

  companion object {
    const val PROVIDER_ID = "zeta-hsm-token-signing"
    const val HSM_PROVIDER_PRIORITY = 200

    const val CONFIG_ENDPOINT = "endpoint"
    const val CONFIG_KEY_ID = "keyId"
    const val CONFIG_PRIORITY = "priority"

    /** SPI scope key for the fail-closed guard. */
    const val CONFIG_FAIL_CLOSED = "failClosed"

    val CONFIG_PROPERTIES: List<ProviderConfigProperty> =
        ProviderConfigurationBuilder.create()
            // CONFIG_PRIORITY
            .property()
            .name(CONFIG_PRIORITY)
            .type(ProviderConfigProperty.STRING_TYPE)
            .label("Priority")
            .helpText("Provider priority. Higher value wins over lower-priority key providers. Default: 200.")
            .defaultValue(HSM_PROVIDER_PRIORITY.toString())
            // CONFIG_ENDPOINT
            .add()
            .property()
            .name(CONFIG_ENDPOINT)
            .type(ProviderConfigProperty.STRING_TYPE)
            .label("HSM Proxy Endpoint")
            .helpText("gRPC address of the HSM Proxy (e.g., hsm-sim:50051).")
            // CONFIG_KEY_ID
            .add()
            .property()
            .name(CONFIG_KEY_ID)
            .type(ProviderConfigProperty.STRING_TYPE)
            .label("Key ID")
            .helpText("Identifier of the signing key in the HSM (e.g., zeta-guard-keycloak-token-es256-v1.p256).")
            .add()
            .build()
  }
}
