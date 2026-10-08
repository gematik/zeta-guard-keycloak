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
package de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.isSuccessStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.rememberLastClientIp
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.mobile.MobileOpaGate
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import jakarta.ws.rs.core.Response
import java.util.stream.Collectors
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException
import org.keycloak.TokenVerifier
import org.keycloak.events.Details
import org.keycloak.events.Errors
import org.keycloak.models.ClientModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider
import org.keycloak.representations.AccessToken
import org.keycloak.services.CorsErrorResponseException
import org.keycloak.services.managers.AuthenticationManager

private val logger: Logger = Logger.getLogger(ZetaGuardEmailBindingTokenExchangeProvider::class.java)

/**
 * Internal token exchange for mobile clients: swaps the reduced E-Mail-Binding-Token for
 * FULL tokens once the user binding is complete.
 *
 * The client sends `grant_type=token-exchange` with `subject_token=<E-Mail-Binding-Token>`,
 * `subject_token_type=access_token`, its `client_assertion` (private_key_jwt) and a DPoP proof.
 * The exchange succeeds ONLY in status bound (emailVerificationState == VERIFIED) — otherwise
 * 400 invalid_grant. If the binding token expires before /verify, the client restarts via OIDC.
 *
 * Differences to [StandardTokenExchangeProvider]:
 * - only SEK_IDP clients (SMC-B clients keep the standard behavior)
 * - the DPoP-bound subject token is ACCEPTED (the standard provider rejects sender-constrained
 *   tokens)
 * - restores the originally authorized scopes and strips zeta:email-binding / zeta:email-verify
 */
class ZetaGuardEmailBindingTokenExchangeProvider(private val opaConfig: OPAConfig = OPAConfig()) : StandardTokenExchangeProvider() {

  private var restoredScopeParam: String? = null

  override fun supports(context: TokenExchangeContext): Boolean {
    if (!super.supports(context)) {
      return false
    }

    if (!OidcFlowSettings.isEnabled()) {
      return false
    }

    val clientData = ZetaGuardDataService(DefaultEMCreator(context.session)).findClientData(context.client.clientId)
    if (clientData?.clientAuthMethod != ClientAuthMethod.SEK_IDP) {
      context.unsupportedReason = "Email-binding token exchange supports SEK_IDP clients only"
      return false
    }

    if (!carriesEmailBindingScopeUnverified(context.params.subjectToken)) {
      context.unsupportedReason = "Email-binding token exchange supports email-binding subject tokens only"
      return false
    }

    return true
  }

  /**
   * Adapted from [StandardTokenExchangeProvider.tokenExchange] — same validation + issuing path, but
   * with the ZETA email-binding checks in place of the sender-constrained-token rejection.
   */
  override fun tokenExchange(): Response {
    // Parent still holds Keycloak's TokenManager. [ZetaGuardTokenManager] runs
    // OIDCRefreshTokenMapper so PDP TTLs (A_28527) reach the refresh token, not only the access token.
    tokenManager = ZetaGuardTokenManager()
    val subjectTokenString = context.params.subjectToken

    event.detail(Details.REQUESTED_TOKEN_TYPE, context.params.requestedTokenType)

    val authResult =
        AuthenticationManager.verifyIdentityToken(
            session, realm, session.context.uri, clientConnection, true, true, null, false, subjectTokenString, context.headers) {}
          ?: raiseError(Errors.INVALID_TOKEN, OAuthErrorException.INVALID_REQUEST, "Invalid token", "subject_token validation failure")

    val token = authResult.token()

    // The binding token is single-client: it must have been issued to the very client doing the exchange.
    if (token.issuedFor != client.clientId) {
      raiseError(Errors.INVALID_TOKEN, OAuthErrorException.INVALID_GRANT, "Subject token was not issued to this client")
    }

    // Only the reduced E-Mail-Binding-Token may enter this exchange (full tokens have no reason to).
    val subjectScopes = token.scope?.split(' ')?.toSet().orEmpty()
    if (setOf(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION).intersect(subjectScopes).isEmpty()) {
      raiseError(Errors.INVALID_TOKEN, OAuthErrorException.INVALID_GRANT, "Subject token is not an email-binding token")
    }

    // The gate itself: full tokens ONLY in status bound.
    val clientData = ZetaGuardDataService(DefaultEMCreator(session)).findClientData(client.clientId)
    if (clientData == null || clientData.registrationStatus != ClientRegistrationStatus.CONFIRMED) {
      raiseError(
          Errors.INVALID_TOKEN,
          OAuthErrorException.INVALID_GRANT,
          "Email binding not complete",
          "email binding state is ${clientData?.registrationStatus}",
      )
    }

    val tokenUser = authResult.user()
    val tokenSession =
        authResult.session()
            ?: raiseError(Errors.INVALID_TOKEN, OAuthErrorException.INVALID_GRANT, "Invalid token", "missing user session")

    event.user(tokenUser)
    event.detail(Details.USERNAME, tokenUser.username)
    if (token.sessionId != null) {
      event.session(tokenSession)
    }
    event.detail(Details.SUBJECT_TOKEN_CLIENT_ID, token.issuedFor)

    restoredScopeParam = originalScopeParam(tokenSession)
    context.restrictedScopes = grantedScopeNames(restoredScopeParam, tokenUser)

    val clientSession = tokenSession.getAuthenticatedClientSessionByClient(client.id)
    MobileOpaGate(opaConfig)
        .enforce(
            MobileOpaGate.Request(
                session = session,
                client = client,
                userSession = tokenSession,
                grantType = OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE,
                scopes = MobileOpaGate.scopesOf(restoredScopeParam, clientSession),
                audiences = MobileOpaGate.audiencesOf(formParams, clientSession),
                clientData = clientData,
                cors = cors,
                event = event,
            ),
        )

    logger.infof(
        "Email-binding token exchange for bound mobile client »%s« → issuing full tokens (scope »%s«)",
        client.clientId,
        restoredScopeParam)

    clientData.lastAccess = currentTime()


    val response = exchangeClientToClient(tokenUser, tokenSession, token, true)
    if (response.isSuccessStatus()) {
      rememberLastClientIp(session, client)
    }
    return response
  }

  override fun getRequestedScope(token: AccessToken, targetAudienceClients: List<ClientModel>): String? = restoredScopeParam

  /**
   * Everything the client would have been granted on a plain /token — the PAR scope plus the client's
   * default scopes — with only the email-binding optional scopes taken away.
   */
  private fun grantedScopeNames(scopeParam: String?, user: UserModel): Set<String> =
      TokenManager.getRequestedClientScopes(session, scopeParam, client, user)
          .map { it.name }
          .filter { it !in EMAIL_BINDING_SCOPE_NAMES }
          .collect(Collectors.toSet())

  /** The scope the client pushed via PAR, kept on the client session and untouched by the reduced token. */
  private fun originalScopeParam(userSession: UserSessionModel?): String? {
    val clientSession = userSession?.getAuthenticatedClientSessionByClient(client.id) ?: return null
    return clientSession.getNote(OAuth2Constants.SCOPE)
  }

  private fun raiseError(eventError: String, oauthError: String, message: String, reason: String = message): Nothing {
    event.detail(Details.REASON, reason)
    event.error(eventError)
    throw CorsErrorResponseException(cors, oauthError, message, Response.Status.BAD_REQUEST)
  }
}

private fun carriesEmailBindingScopeUnverified(rawSubjectToken: String?): Boolean {
  if (rawSubjectToken.isNullOrBlank()) return false
  val scope = runCatching { TokenVerifier.create(rawSubjectToken, AccessToken::class.java).token.scope }.getOrNull()
  return scope?.split(' ')?.contains(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION) == true
}
