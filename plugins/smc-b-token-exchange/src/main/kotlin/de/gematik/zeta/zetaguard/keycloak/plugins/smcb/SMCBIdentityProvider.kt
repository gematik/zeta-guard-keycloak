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

import de.gematik.zeta.zetaguard.keycloak.AbstractZetaGuardIdentityProvider
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJsonNode
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCBUSER_TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.getSMCBContext
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.protocol.oidc.TokenExchangeContext

/**
 * As of version 26.4.7, Keycloak does not implement external-to-internal token exchange in V2.
 *
 * We try to use as much as possible from the V2 OIDC provider implementation. For details, see https://www.keycloak.org/securing-apps/token-exchange
 *
 * Realm configuration in 11-create-smc-b-identity-provider.sh
 */
open class SMCBIdentityProvider(session: KeycloakSession, config: OIDCIdentityProviderConfig) : AbstractZetaGuardIdentityProvider(session, config) {

  private fun profile(subject: String, email: String, name: String, preferredUsername: String, givenName: String, familyName: String) =
      """{
              "sub": "$subject",
              "name": "$name",
              "given_name": "$givenName",
              "family_name": "$familyName",
              "preferred_username": "$preferredUsername",
              "email": "$email"
            }""".toJsonNode()

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

  override fun updateUserModel(context: BrokeredIdentityContext, userModel: UserModel) {
    val smcbContext = context.getSMCBContext()

    userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_NAME, smcbContext.subjectCommonName)
    smcbContext.subjectOrganisation?.let { userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_ORGANISATION, it) }
        ?: userModel.removeAttribute(ATTRIBUTE_SMCBUSER_ORGANISATION)
    userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_TELEMATIK_ID, smcbContext.telematikID)
    userModel.setSingleAttribute(ATTRIBUTE_SMCBUSER_PROFESSION_OID, smcbContext.professionOID)
  }

  override fun professionOid(context: BrokeredIdentityContext): String = context.getSMCBContext().professionOID

  /**
   * See [preprocessFederatedIdentity]
   *
   * We will handle nonces ourselves
   */
  override fun getConfig(): OIDCIdentityProviderConfig = super.config.apply { isDisableNonce = true }
}

private fun mailaddress(subject: String) = "$subject@gematik.de"
