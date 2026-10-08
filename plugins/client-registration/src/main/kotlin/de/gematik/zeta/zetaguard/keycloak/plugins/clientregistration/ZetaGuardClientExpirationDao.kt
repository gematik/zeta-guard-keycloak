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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.minus
import de.gematik.zeta.zetaguard.keycloak.jpa.EntityManagerCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.FIND_EXPIRED_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.FIND_EXPIRED_USER_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.FIND_OLDEST_CLIENTS
import jakarta.persistence.EntityManager
import kotlinx.datetime.DateTimePeriod

/**
 * Service for managing admin event logs in the Keycloak database.
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26269
 *
 * This service provides methods to retrieve the previous hash, find all admin event logs, and save new admin event log entries.
 */
class ZetaGuardClientExpirationDao
/** @param emCreator A lambda that provides an [EntityManager] instance for database operations. */
constructor(emCreator: EntityManagerCreator) {
  private val entityManager by lazy { emCreator.invoke() }

  fun findExpiredClientRegistrations(clientRegistrationTTL: DateTimePeriod): List<String> =
      findExpiredClientData(clientRegistrationTTL, ClientAttestationState.PENDING)

  fun findExpiredClients(clientTTL: DateTimePeriod): List<String> = findExpiredClientData(clientTTL, ClientAttestationState.VALID)

  private fun findExpiredClientData(ttl: DateTimePeriod, state: ClientAttestationState): List<String> =
      entityManager
          .createNamedQuery(FIND_EXPIRED_CLIENT_DATA, String::class.java)
          .setParameter("state", state)
          .setParameter("expirationTime", currentTime().minus(ttl))
          .resultList

  fun findExpiredUsers(ttl: DateTimePeriod): List<String> =
      entityManager.createNamedQuery(FIND_EXPIRED_USER_DATA, String::class.java).setParameter("expirationTime", currentTime().minus(ttl)).resultList

  fun findOldestClients(userName: String): List<String> =
      entityManager.createNamedQuery(FIND_OLDEST_CLIENTS, String::class.java).setParameter("userName", userName).resultList
}
