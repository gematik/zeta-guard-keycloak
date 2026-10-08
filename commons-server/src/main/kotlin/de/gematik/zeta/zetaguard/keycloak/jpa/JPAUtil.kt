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
package de.gematik.zeta.zetaguard.keycloak.jpa

import jakarta.persistence.EntityManager
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.models.jpa.JpaRealmProvider
import org.keycloak.models.jpa.JpaUserProvider

val KeycloakSession.entityManager: EntityManager
  get() = getProvider(JpaConnectionProvider::class.java).entityManager

val KeycloakSession.realmProvider: JpaRealmProvider
  get() = JpaRealmProvider(this, this.entityManager, null, null)

val KeycloakSession.userProvider: JpaUserProvider
  get() = JpaUserProvider(this, this.entityManager)

typealias EntityManagerCreator = () -> EntityManager

class DefaultEMCreator(private val keycloakSession: KeycloakSession) : EntityManagerCreator {
  override fun invoke(): EntityManager = keycloakSession.entityManager
}
