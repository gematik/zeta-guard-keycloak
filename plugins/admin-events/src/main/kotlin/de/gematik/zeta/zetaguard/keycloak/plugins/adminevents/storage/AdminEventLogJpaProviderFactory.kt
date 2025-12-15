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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage

import org.keycloak.Config
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider
import org.keycloak.connections.jpa.entityprovider.JpaEntityProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

const val ADMIN_EVENTS_JPA_PROVIDER_ID = "zeta-guard-admin-events-jpa"

/** Factory for creating instances of [AdminEventLogJpaProvider]. */
class AdminEventLogJpaProviderFactory : JpaEntityProviderFactory {
  override fun create(keycloakSession: KeycloakSession): JpaEntityProvider = AdminEventLogJpaProvider()

  override fun init(scope: Config.Scope) {}

  override fun postInit(keycloakSessionFactory: KeycloakSessionFactory) {}

  override fun close() {}

  override fun getId() = ADMIN_EVENTS_JPA_PROVIDER_ID
}
