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

import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_DEFAULT_HTTP_SPI_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_HTTP_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_MTLS_HTTP_CLIENT_ID
import org.keycloak.Config
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.connections.httpclient.DefaultHttpClientFactory
import org.keycloak.connections.httpclient.HttpClientBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

/**
 * Outbound HTTP client for the SekIDP endpoints that demand client authentication — PAR and token
 * (self_signed_tls_client_auth, A_23183). Analogous to Keycloak's `OTelHttpClientFactory`: a second
 * [DefaultHttpClientFactory] that shares the default client's full connections-http-client SPI configuration —
 * truststore and hostname verification, proxy mappings, timeouts, pool sizing — and differs only in the key material
 * it presents. Obtain it via `session.getProvider(HttpClientProvider::class.java, SEKIDP_MTLS_HTTP_CLIENT_ID)`.
 *
 * The key material comes from [SekIDPIdentityProviderFactory.mtlsConfig], so the client certificate presented here
 * is the one published in the Guard's entity statement. That config is resolved in the IdP factory's `init`, hence it
 * is read here in [postInit]: Keycloak calls `init` on every provider factory before calling any `postInit`.
 *
 * With [order] 0 this factory never becomes the default HTTP client (Keycloak picks the highest order > 0, else "default").
 */
class SekIDPHttpClientFactory : DefaultHttpClientFactory() {
  private var mtlsConfig: MTLSClientConfig? = null

  override fun getId() = SEKIDP_MTLS_HTTP_CLIENT_ID

  override fun init(config: Config.Scope) {
    // Use default configuration
    super.init(Config.scope(KEYCLOAK_DEFAULT_HTTP_SPI_NAME, KEYCLOAK_HTTP_CLIENT_ID))
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    super.postInit(factory)

    val sekIDPIdentityProviderFactory = factory.getProviderFactory(IdentityProvider::class.java, SEKIDP_IDENTITY_PROVIDER_ID) as SekIDPIdentityProviderFactory

    mtlsConfig = sekIDPIdentityProviderFactory.mtlsConfig()
  }

  override fun newHttpClientBuilder(session: KeycloakSession): HttpClientBuilder =
      super.newHttpClientBuilder(session).apply { mtlsConfig?.let { keyStore(it.keystore, it.keystorePassword) } }
}
