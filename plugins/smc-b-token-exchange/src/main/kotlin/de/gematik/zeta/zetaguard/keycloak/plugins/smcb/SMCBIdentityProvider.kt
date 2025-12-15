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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_CLIENT_IDS
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_MAX_CLIENTS
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
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

/**
 * As of version 26.4.5, Keycloak does not implement external-to-internal token exchange in V2.
 *
 * We try to use as much as possible from the V2 OIDC provider implementation. For details, see https://www.keycloak.org/securing-apps/token-exchange
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
    val accessToken = subjectToken.toAccessToken()
    val subject = accessToken.subject ?: throw IllegalArgumentException("Access token has no subject")
    val mailaddress = mailaddress(subject)

    return extractIdentityFromProfile(
            tokenExchangeContext.event,
            profile(
                subject,
                accessToken.email ?: mailaddress,
                accessToken.name ?: subject,
                accessToken.preferredUsername ?: mailaddress,
                accessToken.givenName ?: subject,
                accessToken.familyName ?: subject,
            ),
        )
        .apply {
          contextData[EXCHANGE_PROVIDER] = config.alias
          idp = this@SMCBIdentityProvider
          modelUsername = subject
        }
  }

  override fun importNewUser(session: KeycloakSession, realm: RealmModel, user: UserModel, context: BrokeredIdentityContext) {
    updateBrokeredUser(session, realm, user, context)
  }

  /**
   * Remember and count the clients of an SMC-B User (identified by Telematik-ID).
   *
   * Set user-associated data as described in https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26972
   *
   * The maximum number of clients per user is limited: https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25748
   */
  override fun updateBrokeredUser(session: KeycloakSession, realm: RealmModel, user: UserModel, context: BrokeredIdentityContext) {
    // See [org.keycloak.models.cache.infinispan.UserAdapter]: Changes will not be persisted otherwise
    val userModel = if (user is CachedUserModel) user.delegateForUpdate else user
    val clientId = session.context.client.clientId
    val clientIds = user.attributes[ATTRIBUTE_SMCBUSER_CLIENT_IDS]?.toMutableSet() ?: mutableSetOf()

    if (clientIds.add(clientId)) {
      if (clientIds.size > maxClients()) {
        throw ClientRegistrationException("Too many clients for user ${userModel.username}")
      }

      userModel.setAttribute(ATTRIBUTE_SMCBUSER_CLIENT_IDS, clientIds.toList())

      val smcbContext = context.getSMCBContext()

      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_NAME, smcbContext.subjectName)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_ORGANISATION, smcbContext.subjectOrganisation)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_TELEMATIK_ID, smcbContext.telematikID)
      userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_PROFESSION_OID, smcbContext.professionOID)
    }
  }

  /**
   * See [preprocessFederatedIdentity]
   *
   * We will handle nonces ourselves
   */
  override fun getConfig(): OIDCIdentityProviderConfig = super.config.apply { isDisableNonce = true }

  private fun maxClients() = MAX_CLIENTS.toInt()
}

private fun mailaddress(subject: String) = "$subject@gematik.de"
