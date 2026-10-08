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
package de.gematik.zeta.zetaguard.keycloak.plugins.authorization_code

import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_COLLECT_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_VERIFY_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_BINDING_TOKEN_TTL_SECONDS
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_BINDING_MODE
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_EMAIL_HINT
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.isSuccessStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.rememberLastClientIp
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpService
import de.gematik.zeta.zetaguard.keycloak.commons.email.maskEmail
import de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EMAIL_BINDING_SCOPE_NAMES
import de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.withTokenScopesReducedTo
import de.gematik.zeta.zetaguard.keycloak.plugins.mobile.MobileOpaGate
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import jakarta.ws.rs.core.Response
import java.util.function.Function
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.common.util.Time
import org.keycloak.email.EmailException
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.protocol.oidc.grants.AuthorizationCodeGrantType
import org.keycloak.protocol.oidc.grants.OAuth2GrantType
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.clientpolicy.ClientPolicyContext

private val logger: Logger = Logger.getLogger(ZetaGuardAuthorizationCodeGrantType::class.java)

class ZetaGuardAuthorizationCodeGrantType(private val opaConfig: OPAConfig = OPAConfig()) : AuthorizationCodeGrantType() {
  private var issuance: Issuance = Issuance.Passthrough

  /**
   * Replace Keycloak's TokenManager after every context bind.
   *
   * [AuthorizationCodeGrantType.process] always calls [setContext], which assigns
   * `tokenManager` from the request context. Setting it only in [process] would be
   * overwritten by `super.process`. [ZetaGuardTokenManager] runs OIDCRefreshTokenMapper
   * so PDP TTLs (A_28527) reach the refresh token, not only the access token.
   */
  override fun setContext(context: OAuth2GrantType.Context) {
    super.setContext(context)
    tokenManager = ZetaGuardTokenManager()
  }

  override fun process(context: OAuth2GrantType.Context): Response {
    setContext(context)

    issuance = resolveIssuance()

    val response = super.process(context)
    if (issuance is Issuance.Full && response.isSuccessStatus()) {
      rememberLastClientIp(session, client)
    }
    return response
  }

  /** The reduced email-binding token is short-lived and single-purpose — no refresh token. */
  override fun useRefreshToken(): Boolean {
    if (issuance is Issuance.EmailConfirmationRequired) return false
    return super.useRefreshToken()
  }
  /**
   * Down-scope + shorten the reduced token. This is the hook that actually runs for authorization_code
   */
  override fun createTokenResponseBuilder(
      user: UserModel,
      userSession: UserSessionModel,
      clientSessionCtx: ClientSessionContext,
      scopeParam: String?,
      clientPolicyContextGenerator: Function<TokenManager.AccessTokenResponseBuilder, ClientPolicyContext>?,
  ): TokenManager.AccessTokenResponseBuilder {
    val effectiveCtx =
        when (issuance) {
          is Issuance.EmailConfirmationRequired -> clientSessionCtx.withTokenScopesReducedTo(session, bindingScopesFor(user))
          else -> clientSessionCtx
        }

    val fullIssuance = issuance as? Issuance.Full
    if (fullIssuance != null) {
      MobileOpaGate(opaConfig)
          .enforce(
              MobileOpaGate.Request(
                  session = session,
                  client = client,
                  userSession = userSession,
                  grantType = OAuth2Constants.AUTHORIZATION_CODE,
                  scopes = MobileOpaGate.scopesOf(scopeParam, clientSessionCtx.clientSession),
                  audiences = MobileOpaGate.audiencesOf(formParams, clientSessionCtx.clientSession),
                  clientData = fullIssuance.clientData,
                  cors = cors,
                  event = event,
              ),
          )
    } else if (issuance is Issuance.EmailConfirmationRequired) {
      persistRequestedAudience(clientSessionCtx.clientSession)
    }

    val builder = super.createTokenResponseBuilder(user, userSession, effectiveCtx, scopeParam, clientPolicyContextGenerator)
    if (issuance is Issuance.EmailConfirmationRequired) {
      logger.infof("Mobile client »%s« not bound — issuing reduced email-binding token", client.clientId)
      builder.accessToken?.exp((Time.currentTime() + EMAIL_BINDING_TOKEN_TTL_SECONDS).toLong())
    }
    return builder
  }

  /**
   * Decide the `binding_mode` and, for the verify_otp case, generate + "send" (stub) the OTP right here
   */
  override fun addCustomTokenResponseClaims(response: AccessTokenResponse, clientSessionCtx: ClientSessionContext) {
    super.addCustomTokenResponseClaims(response, clientSessionCtx)
    val binding = issuance as? Issuance.EmailConfirmationRequired ?: return

    val user = clientSessionCtx.clientSession.userSession.user
    val storedEmail = user.email

    if (storedEmail.isNullOrBlank() || !user.isEmailVerified) {
      response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] = BINDING_MODE_COLLECT_EMAIL
    } else {
      val otp = EmailOtpService.issue(session, client.clientId)
      try {
        EmailOtpMailer.send(session, storedEmail, otp)
      } catch (e: EmailException) {
        logger.errorf(e, "Failed to send email-binding OTP for client »%s«", client.clientId)
        throw ErrorResponseException("email_send_failed", "Failed to send verification email", Response.Status.INTERNAL_SERVER_ERROR)
      }
      logger.infof("Email-binding OTP (verify_otp) issued for client »%s«", client.clientId)
      binding.clientData.registrationStatus = ClientRegistrationStatus.OTP_PENDING
      response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] = BINDING_MODE_VERIFY_OTP
      response.otherClaims[RESPONSE_MEMBER_EMAIL_HINT] = maskEmail(storedEmail)
    }
  }

  private fun verifiedEmailOf(user: UserModel): String? = user.email?.takeIf { it.isNotBlank() && user.isEmailVerified }

  private fun bindingScopesFor(user: UserModel): Set<String> =
      if (verifiedEmailOf(user) == null) EMAIL_BINDING_SCOPE_NAMES else setOf(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)

  private fun resolveIssuance(): Issuance {
    if (realm.name != ZETA_REALM || !OidcFlowSettings.isEnabled()) {
      return Issuance.Passthrough
    }

    val clientData = ZetaGuardDataService(DefaultEMCreator(session)).findClientData(client.clientId)
    if (clientData?.clientAuthMethod != ClientAuthMethod.SEK_IDP) {
      return Issuance.Passthrough
    }
    return if (clientData.registrationStatus == ClientRegistrationStatus.CONFIRMED) Issuance.Full(clientData)
    else Issuance.EmailConfirmationRequired(clientData)
  }

  /**
   * Keep the token-request `audience` on the client session for the email-binding exchange.
   *
   * Unbound clients skip OPA here and get a reduced binding token. The later token-exchange
   * request no longer carries `audience`, but [MobileOpaGate] still needs the original value
   * for the PDP check when issuing the full token.
   */
  private fun persistRequestedAudience(clientSession: AuthenticatedClientSessionModel) {
    val audience = formParams.getFirst(OAuth2Constants.AUDIENCE)
    if (!audience.isNullOrBlank()) {
      clientSession.setNote(OAuth2Constants.AUDIENCE, audience)
    }
  }
}
private sealed interface Issuance {
  data object Passthrough : Issuance

  data class Full(val clientData: ZetaGuardClientData) : Issuance

  data class EmailConfirmationRequired(val clientData: ZetaGuardClientData) : Issuance
}
