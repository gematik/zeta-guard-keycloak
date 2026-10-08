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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_CREATED_AT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_LAST_ACCESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_MAX_CLIENTS
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardExpirationService
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.getSMCBContext
import org.keycloak.broker.oidc.OIDCIdentityProvider
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.cache.CachedUserModel
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.services.clientregistration.ClientRegistrationException

private val MAX_CLIENTS = System.getenv(ENV_MAX_CLIENTS) ?: "256"
private val maxClients = MAX_CLIENTS.toInt()

/**
 * As of version 26.4.7, Keycloak does not implement external-to-internal token exchange in V2.
 *
 * We try to use as much as possible from the V2 OIDC provider implementation. For details, see https://www.keycloak.org/securing-apps/token-exchange
 *
 * Realm configuration in 11-create-smc-b-identity-provider.sh
 */
open class SMCBIdentityProvider(session: KeycloakSession, config: OIDCIdentityProviderConfig) : OIDCIdentityProvider(session, config) {
  private fun profile(subject: String, email: String, name: String, preferredUsername: String, givenName: String, familyName: String) =
      ObjectMapper()
          .readTree(
              """{
              "sub": "$subject",
              "name": "$name",
              "given_name": "$givenName",
              "family_name": "$familyName",
              "preferred_username": "$preferredUsername",
              "email": "$email"
            }"""
          )

  /**
   * Inspired by [org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.validateExternalTokenThroughUserInfo] which is called by the legacy V1
   * version.
   *
   * User information is obtained from token
   */
  override fun exchangeExternalTokenV2Impl(tokenExchangeContext: TokenExchangeContext): BrokeredIdentityContext {
    val subjectToken = tokenExchangeContext.params.subjectToken
    val token = subjectToken.toJsonWebToken()
    val subject = token.subject ?: error("JWT has no subject")
    val username = subject.toSpicyHash()
    val mailaddress = mailaddress(username)

    return extractIdentityFromProfile(tokenExchangeContext.event, profile(username, mailaddress, username, mailaddress, username, username)).apply {
      contextData[EXCHANGE_PROVIDER] = config.alias
      idp = this@SMCBIdentityProvider
      modelUsername = username
    }
  }

  override fun importNewUser(session: KeycloakSession, realm: RealmModel, userModel: UserModel, context: BrokeredIdentityContext) {
    val dataService = ZetaGuardDataService(DefaultEMCreator(session))

    dataService.createUserData(userModel.username)
    userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_CREATED_AT, currentTime().toISO8601())

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

    // See [org.keycloak.models.cache.infinispan.UserAdapter]: Changes will not be persisted without direct access
    val userModel = if (user is CachedUserModel) user.delegateForUpdate else user
    val clientId = session.context.client.clientId
    val userData =
        dataService.findUserData(userModel.username) ?: throw ClientRegistrationException("Could not find user data for »${userModel.username}«")
    val clientData = dataService.findClientData(clientId) ?: throw ClientRegistrationException("Could not find client data for »${clientId}«")
    val clientIds = userData.clients.map { it.id }.toMutableSet()
    val clientExpirationService = ZetaGuardExpirationService(session)
    val now = currentTime()

    if (clientIds.add(clientId)) { // A_25748-02
      if (clientIds.size > maxClients && !clientExpirationService.removeOldestClient(userModel.username)) {
        throw ClientRegistrationException("Too many clients for user »${userModel.username}«").also {
          SecurityEventLogger.logClientRegistrationFail(clientId = clientId, reason = "too_many_clients_registered")
        }
      }

      userData.clients.add(clientData)
      clientData.userData = userData

      val smcbContext = context.getSMCBContext()

      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_NAME, smcbContext.subjectCommonName)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_ORGANISATION, smcbContext.subjectOrganisation)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_TELEMATIK_ID, smcbContext.telematikID)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_PROFESSION_OID, smcbContext.professionOID)
    }

    // Gather data for expiration, https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28808
    userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_LAST_ACCESS, now.toISO8601())
    userData.lastAccess = now
    clientData.lastAccess = now
  }

  /**
   * See [preprocessFederatedIdentity]
   *
   * We will handle nonces ourselves
   */
  override fun getConfig(): OIDCIdentityProviderConfig = super.config.apply { isDisableNonce = true }
}

private fun mailaddress(subject: String) = "$subject@gematik.de"
