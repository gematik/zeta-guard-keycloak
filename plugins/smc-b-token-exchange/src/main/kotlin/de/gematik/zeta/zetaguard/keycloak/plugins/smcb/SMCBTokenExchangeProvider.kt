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

import de.gematik.zeta.zetaguard.keycloak.commons.SMCB_ISSUER
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import jakarta.ws.rs.core.Response
import org.keycloak.OAuth2Constants
import org.keycloak.broker.provider.ExchangeExternalToken
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.events.Errors
import org.keycloak.models.ClientModel
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider
import org.keycloak.representations.AccessToken
import org.keycloak.services.CorsErrorResponseException
import org.keycloak.services.managers.UserSessionManager
import org.keycloak.services.resources.IdentityBrokerService.getIdentityProvider

/** External to internal token exchange provider for SMC-B created tokens */
open class SMCBTokenExchangeProvider : StandardTokenExchangeProvider() {
    override fun supports(context: TokenExchangeContext) =
        isExternalInternalTokenExchangeRequest(context)

    /** @see [org.keycloak.broker.oidc.AbstractOAuth2IdentityProvider.exchangeExternal] */
    override fun getVersion(): Int = 2

    override fun validateAudience(
        token: AccessToken,
        disallowOnHolderOfTokenMismatch: Boolean,
        targetAudienceClients: List<ClientModel>,
    ) {
        // Ignore audience checks and allow for public client
    }

    override fun tokenExchange(): Response {
        val subjectToken = context.params.subjectToken
        val subjectTokenType = context.params.subjectTokenType
        val subjectIssuer = getSubjectIssuer(this.context, subjectToken, subjectTokenType)

        // Usually you would now check the validity:
        // AuthenticationManager.AuthResult authResult =
        // AuthenticationManager.verifyIdentityToken(session, realm, session.getContext().getUri(),
        // clientConnection, true, true, null, false, subjectToken, context.getHeaders());

        if (!subjectIssuer.contains(SMCB_ISSUER, true)) {
            throw invalidIssuer()
        }

        return exchangeExternalToken(SMCB_ISSUER, subjectToken)
    }

    /**
     * Adapted from
     * [org.keycloak.protocol.oidc.tokenexchange.AbstractTokenExchangeProvider.exchangeExternalToken]
     */
    override fun exchangeExternalToken(subjectIssuer: String, subjectToken: String): Response {
        val provider = getIdentityProvider(session, subjectIssuer) as ExchangeExternalToken
        val model = session.identityProviders().getByAlias(subjectIssuer)
        val accessToken = subjectToken.toAccessToken()
        val context = provider.exchangeExternal(this, this.context) ?: throw invalidIssuer()
        val user = importUserFromExternalIdentity(context)
        val userSession =
            UserSessionManager(session)
                .createUserSession(
                    realm,
                    user,
                    user.username,
                    clientConnection.remoteHost,
                    "external-exchange",
                    false,
                    null,
                    null,
                )

        provider.exchangeExternalComplete(userSession, context, formParams)

        userSession.setNote(IdentityProvider.EXTERNAL_IDENTITY_PROVIDER, model.alias)
        userSession.setNote(IdentityProvider.FEDERATED_ACCESS_TOKEN, subjectToken)

        context.addSessionNotesToUserSession(userSession)

        return exchangeClientToClient(user, userSession, accessToken, false)
    }

    private fun SMCBTokenExchangeProvider.invalidIssuer(): CorsErrorResponseException =
        CorsErrorResponseException(
                cors,
                Errors.INVALID_ISSUER,
                "Invalid " + OAuth2Constants.SUBJECT_ISSUER + " parameter",
                Response.Status.BAD_REQUEST,
            )
            .also { event.error(Errors.INVALID_ISSUER) }
}
