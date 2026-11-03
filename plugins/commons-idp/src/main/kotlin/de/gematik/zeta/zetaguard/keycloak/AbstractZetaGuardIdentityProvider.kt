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
package de.gematik.zeta.zetaguard.keycloak

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_CREATED_AT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_LAST_ACCESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_MAX_CLIENTS
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardExpirationService
import de.gematik.zeta.zetaguard.keycloak.plugins.toWritableUser
import org.keycloak.broker.oidc.OIDCIdentityProvider
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.services.clientregistration.ClientRegistrationException

private val MAX_CLIENTS = System.getenv(ENV_MAX_CLIENTS) ?: "256"
private val maxClients = MAX_CLIENTS.toInt()

/**
 * Common superclass for 𝛇-Guard IDPs
 */
abstract class AbstractZetaGuardIdentityProvider(session: KeycloakSession, config: OIDCIdentityProviderConfig) :
  OIDCIdentityProvider(session, config) {

  override fun importNewUser(session: KeycloakSession, realm: RealmModel, userModel: UserModel, context: BrokeredIdentityContext) {
    val dataService = ZetaGuardDataService(DefaultEMCreator(session))

    dataService.createUserData(userModel.username)
    userModel.setAccessTime(ATTRIBUTE_USER_CREATED_AT)

    updateBrokeredUser(session, realm, userModel, context)
  }

  /**
   * Remember and count the clients of an SMC-B User (identified by Telematik-ID).
   *
   * Set user-associated data as described in https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26972,
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25650
   *
   * The maximum number of clients per user is limited: https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25748
   */
  override fun updateBrokeredUser(session: KeycloakSession, realm: RealmModel, user: UserModel, context: BrokeredIdentityContext) {
    val dataService = ZetaGuardDataService(DefaultEMCreator(session))
    val userModel = user.toWritableUser()
    val clientId = session.context.client.clientId
    val userData = dataService.findUserData(userModel.username)
      ?: throw ClientRegistrationException("Could not find user data for »${userModel.username}«")
    val clientData = dataService.findClientData(clientId) ?: throw ClientRegistrationException("Could not find client data for »${clientId}«")
    val clientIds = userData.clients.map { it.id }.toMutableSet()
    val now = currentTime()

    if (clientIds.add(clientId)) {
      dataService.evictOldClientsIfNecessary(userModel.username, clientId)

      userData.clients.add(clientData)
      clientData.userData = userData

      updateUserModel(context, userModel)
    }

    userModel.setAccessTime(ATTRIBUTE_USER_LAST_ACCESS)
    userData.lastAccess = now
    clientData.lastAccess = now
  }

  private fun ZetaGuardDataService.evictOldClientsIfNecessary(userName: String, clientId: String) {
    val clientExpirationService = ZetaGuardExpirationService(session)

    // A_25748-02
    // Without the lock, concurrent requests of the same user all see the same count and try to evict the same oldest
    // client, so the limit is exceeded or all but one request fail. The lock is held until the request's transaction
    // ends, so count and eviction below see what a preceding request has committed.
    lockUserData(userName) ?: throw ClientRegistrationException("Could not lock user data for »${userName}«")

    while (countClients(userName, clientId) >= maxClients) {
      if (!clientExpirationService.removeOldestClient(userName)) {
        throw ClientRegistrationException("Too many clients for user »${userName}«").also {
          SecurityEventLogger.logClientRegistrationFail(clientId = clientId, reason = "too_many_clients_registered")
        }
      }
    }
  }

  protected abstract fun updateUserModel(context: BrokeredIdentityContext, userModel: UserModel)
}

// Gather data for expiration, https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28808
private fun UserModel.setAccessTime(attributeName: String) {
  setSingleAttribute(attributeName, currentTime().toISO8601())
}
