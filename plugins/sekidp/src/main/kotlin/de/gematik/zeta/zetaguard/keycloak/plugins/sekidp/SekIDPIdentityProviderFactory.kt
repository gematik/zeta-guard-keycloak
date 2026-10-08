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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import java.security.cert.X509Certificate
import org.keycloak.Config
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.oidc.OIDCIdentityProviderFactory
import org.keycloak.broker.provider.AbstractIdentityProviderFactory
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession

class SekIDPIdentityProviderFactory : AbstractIdentityProviderFactory<SekIDPIdentityProvider>() {

  /** Built once from SPI config in [init] — shared across all SekIDP provider instances. */
  private lateinit var sekIdpHttpClient: SekIdpHttpClient

  /** Published in the Guard's entity statement so the SekIDP can match the presented certificate. Null when mTLS is disabled. */
  internal val mtlsClientCertificate: X509Certificate?
    get() = if (::sekIdpHttpClient.isInitialized) sekIdpHttpClient.clientCertificate else null

  override fun getName() = "ZETA SekIDP (GesundheitsID)"

  override fun getId() = SEKIDP_IDENTITY_PROVIDER_ID

  override fun init(config: Config.Scope) {
    sekIdpHttpClient = SekIdpHttpClient(resolveMtlsConfig(config))
  }

  override fun create(session: KeycloakSession, model: IdentityProviderModel): SekIDPIdentityProvider? =
      if (OidcFlowSettings.isEnabled()) SekIDPIdentityProvider(session, createOIDCIdentityProviderConfig(model), sekIdpHttpClient) else null

  override fun parseConfig(session: KeycloakSession, config: String): MutableMap<String, String?> =
      OIDCIdentityProviderFactory().parseConfig(session, config)

  override fun createConfig(): OIDCIdentityProviderConfig = createOIDCIdentityProviderConfig()

  override fun close() {
    if (::sekIdpHttpClient.isInitialized) sekIdpHttpClient.close()
  }

  private fun createOIDCIdentityProviderConfig(model: IdentityProviderModel? = null) =
      OIDCIdentityProviderConfig(model).apply {
        isTransientUsers = false // Create federated users, so importNewUser/updateBrokeredUser run
      }

  companion object {
    const val CONFIG_MTLS_ENABLED = "mtlsEnabled"
    const val CONFIG_MTLS_KEYSTORE_LOCATION = "mtlsKeystoreLocation"
    const val CONFIG_MTLS_KEYSTORE_PASSWORD = "mtlsKeystorePassword"

    /** Null when mTLS is switched off; a switched-on but incomplete keystore fails here, at start-up, instead of downgrading. */
    private fun resolveMtlsConfig(config: Config.Scope): MtlsClientConfig? =
        if (config.getBoolean(CONFIG_MTLS_ENABLED, false)) {
          MtlsClientConfig(
              keystoreLocation = requireNotNull(config[CONFIG_MTLS_KEYSTORE_LOCATION]) { "»$CONFIG_MTLS_KEYSTORE_LOCATION« must be set when mTLS is enabled" },
              keystorePassword = requireNotNull(config[CONFIG_MTLS_KEYSTORE_PASSWORD]) { "»$CONFIG_MTLS_KEYSTORE_PASSWORD« must be set when mTLS is enabled" },
          )
        } else null
  }
}
