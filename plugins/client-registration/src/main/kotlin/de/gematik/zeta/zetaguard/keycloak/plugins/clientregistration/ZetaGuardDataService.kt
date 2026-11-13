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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.jpa.EntityManagerCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.COUNT_CLIENTS
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.DELETE_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.FIND_CLIENT_OWNER
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.FIND_SEKIDP_REDIRECT_URIS
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.LOCK_USER_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import jakarta.persistence.EntityManager

class ZetaGuardDataService
/** @param emCreator A lambda that provides an [EntityManager] instance for database operations. */
constructor(emCreator: EntityManagerCreator) {
  private val entityManager by lazy { emCreator.invoke() }

  /**
   * Create client data at registration time
   *
   * - The corresponding user is yet unknown and will be set upon first token exchange
   * - The attestation type will be set at registration time for mobile clients and during token exchange for desktop clients
   *
   */
  fun createClientData(clientId: String, clientAuthMethod: ClientAuthMethod): ZetaGuardClientData {
    val now = currentTime()
    val clientData = ZetaGuardClientData(clientId, now, now)

    clientData.attestationState = ClientAttestationState.PENDING
    clientData.clientAuthMethod = clientAuthMethod

    if (clientAuthMethod == ClientAuthMethod.SEK_IDP) {
      clientData.registrationStatus = ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
    }

    entityManager.persist(clientData)

    return clientData
  }

  fun createUserData(userName: String): ZetaGuardUserData {
    val now = currentTime()
    val userData = ZetaGuardUserData(userName, now, now)

    entityManager.persist(userData)
    return userData
  }

  fun findClientData(clientId: String): ZetaGuardClientData? = entityManager.find(ZetaGuardClientData::class.java, clientId)

  fun findSekIdpRedirectUris(realmId: String): List<String> =
      entityManager
          .createNamedQuery(FIND_SEKIDP_REDIRECT_URIS, String::class.java)
          .setParameter("authMethod", ClientAuthMethod.SEK_IDP)
          .setParameter("realmId", realmId)
          .resultList

  fun findUserData(userId: String): ZetaGuardUserData? = entityManager.find(ZetaGuardUserData::class.java, userId)

  /**
   * The ID (username) of the user [clientId] is bound to, if any.
   *
   * Unlike [findClientData], nothing is loaded into the persistence context: a client deleted in bulk afterwards (see [deleteClientDataIfPresent])
   * would otherwise linger there, still referencing its user, and fail the flush once that user is removed too.
   */
  fun findClientOwner(clientId: String): String? =
      entityManager.createNamedQuery(FIND_CLIENT_OWNER, String::class.java).setParameter("clientId", clientId).resultList.firstOrNull()

  /**
   * Locks the user data row until the current transaction ends.
   *
   * A database lock rather than a JVM one, so it also holds between several Keycloak instances. Being a query, it is
   * executed even if the entity is already managed, and pending inserts of the user are flushed before.
   */
  fun lockUserData(userName: String): ZetaGuardUserData? =
      entityManager.createNamedQuery(LOCK_USER_DATA, ZetaGuardUserData::class.java).setParameter("userName", userName).resultList.firstOrNull()

  /**
   * Number of clients bound to the user, as currently stored in the database, not counting [excludedClientId].
   *
   * Excluding the client about to be bound makes the count independent of whether a concurrent request has bound that
   * same client in the meantime.
   */
  fun countClients(userName: String, excludedClientId: String): Long =
      entityManager
          .createNamedQuery(COUNT_CLIENTS, Long::class.java)
          .setParameter("userName", userName)
          .setParameter("clientId", excludedClientId)
          .singleResult
          .toLong()

  /**
   * Like [deleteClientData], but a client that is already gone is no error.
   *
   * For removals that may race with each other, i.e. the expiration job and the eviction of the oldest client: the
   * `DELETE` waits for the row lock of a concurrent deletion and then finds nothing left.
   *
   * @return true if this call deleted the client data
   */
  fun deleteClientDataIfPresent(clientId: String) =
      entityManager.createNamedQuery(DELETE_CLIENT_DATA).setParameter("clientId", clientId).executeUpdate() == 1

  fun deleteClientData(clientId: String) {
    val deletions = entityManager.createNamedQuery(DELETE_CLIENT_DATA).setParameter("clientId", clientId).executeUpdate()

    check(deletions == 1) { "Expected to delete exactly one client data record for clientId »$clientId«, but was $deletions." }
  }

  fun deleteUserData(userName: String) {
    val userData = entityManager.find(ZetaGuardUserData::class.java, userName)!!

    entityManager.remove(userData) // Needs cascading
  }
}
