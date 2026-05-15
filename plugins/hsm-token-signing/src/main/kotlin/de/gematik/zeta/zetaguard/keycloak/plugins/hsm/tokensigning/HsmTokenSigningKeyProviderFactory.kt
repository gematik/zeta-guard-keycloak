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
import java.security.Security
import java.util.Properties
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.keys.KeyProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.slf4j.LoggerFactory

private val log = LoggerFactory.getLogger(HsmTokenSigningKeyProviderFactory::class.java)

/** KeyStore alias used when loading the token-signing key from HsmKeyStoreSpi. */
internal const val TOKEN_KEY_ALIAS = "token"

/**
 * [KeyProviderFactory] for HSM-backed ES256 token signing.
 *
 * The KeyProvider component is registered in each realm by the administrator — either via the Keycloak Admin UI (Realm Settings → Keys → Providers →
 * Add provider → zeta-hsm-token-signing), via `kcadm.sh`, or via Terraform. The plugin does NOT self-register.
 *
 * Configuration properties (set in the Admin UI or via REST API):
 * - **endpoint**: gRPC address of the HSM Proxy (e.g., `hsm-sim:50051`)
 * - **keyId**: key identifier in the HSM (e.g., `zeta-guard-keycloak-token-es256-v1.p256`)
 * - **priority**: provider priority (default 200, higher than software keys at 100)
 *
 * The JCA `HsmProxyProvider` is registered in [postInit] so the HSMPROXY KeyStore type is available for both TLS and token signing. This is the only
 * startup-time side effect.
 */
open class HsmTokenSigningKeyProviderFactory : KeyProviderFactory<HsmTokenSigningKeyProvider> {

  @Volatile private var cachedKeyStore: KeyStore? = null

  override fun getId() = PROVIDER_ID

  override fun init(config: Config.Scope) = Unit

  override fun postInit(factory: KeycloakSessionFactory) {
    // Register the HsmProxyProvider JCA provider at runtime. The java.security entry
    // (security.provider.1) silently fails at JVM startup because the class is in providers/,
    // not on the bootstrap classpath.
    // This is needed for TLS via HSM (KC_HTTPS_KEY_STORE_TYPE=HSMPROXY) and for
    // KeyStore.getInstance("HSMPROXY") in the create() method below.
    if (Security.getProvider(HsmProxyProvider.NAME) == null) {
      Security.addProvider(HsmProxyProvider())
      log.info("🔐 Registered HsmProxyProvider JCA security provider (needed for HSMPROXY KeyStore / TLS) ✅")
    }
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
