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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import org.keycloak.authentication.AuthenticationFlowContext
import org.keycloak.authentication.AuthenticationProcessor
import org.keycloak.authentication.Authenticator
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.IdentityBrokerException
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.broker.provider.util.IdentityBrokerState
import org.keycloak.events.Details
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.services.Urls
import org.keycloak.services.managers.ClientSessionCode
import org.keycloak.services.resources.IdentityBrokerService

/** Alias of the one sectoral IDP `zeta-mobile` ever redirects to. */
private const val SEKIDP_ALIAS = SEKIDP_IDENTITY_PROVIDER_ID

/**
 * Redirects straight to [SEKIDP_ALIAS] from inside the `/authorize` response, instead of Keycloak's stock
 * `identity-provider-redirector`, which first bounces the browser through `/broker/{alias}/login`, a hop that
 * only earns its keep when a rendered login page could show several IDPs to choose from.
 */
class SekIdpDirectRedirectAuthenticator : Authenticator {
  override fun authenticate(context: AuthenticationFlowContext) {
    val providerId = SEKIDP_ALIAS
    val idpModel = context.session.identityProviders().getByAlias(providerId)
    if (idpModel == null || !idpModel.isEnabled) {
      context.attempted()
      return
    }
    // Same guard as the stock identity-provider-redirector: an IDP configured for account-linking only must not
    // be used to log a user in.
    if (idpModel.isLinkOnly == true) {
      throw IdentityBrokerException("Identity Provider [$providerId] is not allowed to perform a login.")
    }

    context.event.detail(Details.IDENTITY_PROVIDER, providerId)

    val identityProvider = IdentityBrokerService.getIdentityProvider(context.session, providerId)
    val response = identityProvider.performLogin(buildAuthenticationRequest(context, identityProvider))

    context.forceChallenge(response)
  }

  private fun buildAuthenticationRequest(
      context: AuthenticationFlowContext,
      identityProvider: UserAuthenticationIdentityProvider<*>,
  ): AuthenticationRequest {
    val authSession = context.authenticationSession
    val relayState = ClientSessionCode(context.session, context.realm, authSession).getOrGenerateCode()
    val clientData = if (identityProvider.supportsLongStateParameter()) AuthenticationProcessor.getClientData(context.session, authSession) else null
    val state = IdentityBrokerState.decoded(relayState, authSession.client.id, authSession.client.clientId, authSession.tabId, clientData)
    val redirectUri = Urls.identityProviderAuthnResponse(context.uriInfo.baseUri, SEKIDP_ALIAS, context.realm.name).toString()

    return AuthenticationRequest(context.session, context.realm, authSession, context.httpRequest, context.uriInfo, state, redirectUri)
  }

  override fun action(context: AuthenticationFlowContext) = Unit

  override fun requiresUser() = false

  override fun configuredFor(session: KeycloakSession, realm: RealmModel, user: UserModel) = true

  override fun setRequiredActions(session: KeycloakSession, realm: RealmModel, user: UserModel) = Unit

  override fun close() = Unit
}
