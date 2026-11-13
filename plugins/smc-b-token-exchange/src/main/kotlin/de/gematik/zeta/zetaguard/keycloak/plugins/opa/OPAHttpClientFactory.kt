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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_DEFAULT_HTTP_SPI_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_HTTP_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.OPA_HTTP_CLIENT_ID
import org.keycloak.Config
import org.keycloak.connections.httpclient.DefaultHttpClientFactory

/**
 * Outbound HTTP client for the OPA requests. By default uses Keycloak default client configuration.
 */
class OPAHttpClientFactory : DefaultHttpClientFactory() {
  override fun getId() = OPA_HTTP_CLIENT_ID

  override fun init(config: Config.Scope) {
    // Use default configuration
    super.init(Config.scope(KEYCLOAK_DEFAULT_HTTP_SPI_NAME, KEYCLOAK_HTTP_CLIENT_ID))
  }
}
