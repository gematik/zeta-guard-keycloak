/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.wellknown

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SERVICE_DOCUMENTATION_URI
import de.gematik.zeta.zetaguard.keycloak.commons.server.WELLKNOWN_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.toURI
import java.lang.System.getenv
import java.net.URI
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.provider.ProviderConfigurationBuilder
import org.keycloak.wellknown.WellKnownProviderFactory

/**
 * Provide REST endpoint for 𝛇-Guard well-known configuration as defined in https://github.com/gematik/zeta/blob/main/src/schemas/as-well-known.yaml
 */
class ZetaGuardWellKnownProviderFactory : WellKnownProviderFactory {
  override fun create(session: KeycloakSession) = ZetaGuardWellKnownProvider(session)

  override fun init(config: Config.Scope) {}

  override fun postInit(factory: KeycloakSessionFactory) {}

  override fun close() {}

  override fun getId() = WELLKNOWN_PROVIDER_ID

  override fun getPriority() = 100

  override fun getConfigMetadata(): List<ProviderConfigProperty> = ProviderConfigurationBuilder.create().build()

  companion object {
    @JvmStatic private val log = Logger.getLogger(ZetaGuardWellKnownProviderFactory::class.java)

    private lateinit var serviceUri: URI
    private val defaultgetenv = { getenv(ENV_SERVICE_DOCUMENTATION_URI) }

    internal val DEFAULT_URI = URI("https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/")

    internal fun serviceDocumentationUri(getEnv: () -> String? = defaultgetenv): URI =
        if (this::serviceUri.isInitialized) {
          serviceUri
        } else {
          getEnv()
              .toURI()
              .mapLeft { log.warn("Environment variable »$ENV_SERVICE_DOCUMENTATION_URI« contains no valid URI: ${it.message}") }
              .fold(ifLeft = { DEFAULT_URI }, ifRight = { it })
        }
  }
}
