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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_RESOURCE_ID
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.resource.RealmResourceProviderFactory

/**
 * Registers the [ZetaEmailBindingResourceProvider] under `.../realms/{realm}/zeta/...`
 * ([ZETA_RESOURCE_ID] is the first path segment / provider id).
 */
class ZetaEmailBindingResourceProviderFactory : RealmResourceProviderFactory {
  override fun getId() = ZETA_RESOURCE_ID

  override fun create(session: KeycloakSession): RealmResourceProvider? =
      if (OidcFlowSettings.isEnabled()) ZetaEmailBindingResourceProvider(session) else null

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // No-op
  }

  override fun close() {
    // No-op
  }
}
