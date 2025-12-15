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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents

import de.gematik.zeta.zetaguard.keycloak.commons.server.ADMIN_EVENTS_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.DefaultEMCreator
import org.keycloak.Config
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

/**
 * Factory for creating instances of [AdminEventLoggerProvider].
 *
 * See META-INF/services/org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory
 */
class AdminEventLoggerProviderFactory : EventListenerProviderFactory {
  override fun create(session: KeycloakSession): EventListenerProvider =
      AdminEventLoggerProvider(AdminEventLogStorageService(DefaultEMCreator(session)))

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // No-op
  }

  override fun close() {
    // No-op
  }

  override fun getId() = ADMIN_EVENTS_PROVIDER_ID
}
