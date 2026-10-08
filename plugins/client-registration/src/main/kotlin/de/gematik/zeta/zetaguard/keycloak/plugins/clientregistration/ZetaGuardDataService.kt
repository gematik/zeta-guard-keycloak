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
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.DELETE_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import jakarta.persistence.EntityManager

class ZetaGuardDataService
/** @param emCreator A lambda that provides an [EntityManager] instance for database operations. */
constructor(emCreator: EntityManagerCreator) {
  private val entityManager by lazy { emCreator.invoke() }

  /** Create client data at registration, user is yet unknown and will be set upon first token exchange */
  fun createClientData(clientId: String, clientAuthMethod: ClientAuthMethod = ClientAuthMethod.SMC_B): ZetaGuardClientData {
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

  fun findUserData(userId: String): ZetaGuardUserData? = entityManager.find(ZetaGuardUserData::class.java, userId)

  fun deleteClientData(clientId: String) {
    val deletions = entityManager.createNamedQuery(DELETE_CLIENT_DATA).setParameter("clientId", clientId).executeUpdate()

    check(deletions == 1) { "Expected to delete exactly one client data record for clientId »$clientId«, but was $deletions." }
  }

  fun deleteUserData(userName: String) {
    val userData = entityManager.find(ZetaGuardUserData::class.java, userName)!!

    entityManager.remove(userData) // Needs cascading
  }
}
