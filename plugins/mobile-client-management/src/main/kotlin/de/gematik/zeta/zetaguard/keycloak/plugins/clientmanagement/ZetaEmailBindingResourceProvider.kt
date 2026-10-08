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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_RESEND_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_VERIFY_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.USERINFO_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpService
import de.gematik.zeta.zetaguard.keycloak.commons.email.maskEmail
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.UserInfoEmailResource
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.FormParam
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.email.EmailException
import org.keycloak.models.UserModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.cache.CachedUserModel
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.managers.AppAuthManager
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.resource.RealmResourceProvider

private val logger: Logger = Logger.getLogger(ZetaEmailBindingResourceProvider::class.java)

class ZetaEmailBindingResourceProvider(private val session: KeycloakSession) : RealmResourceProvider {
  override fun getResource(): Any = this

  /** collect_email: store the submitted email, generate + "send" (stub) an OTP, move → OTP_PENDING. */
  @POST
  @Path(BIND_EMAIL_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun bindEmail(@FormParam("email") email: String?): Response {
    if (email.isNullOrBlank()) {
      return Response.status(Response.Status.BAD_REQUEST).entity(mapOf("status" to "missing_email")).build()
    }
    val authResult = authorize(SCOPE_EMAIL_BINDING) ?: return unauthorized()
    val clientData = loadMobileClientData(authResult) ?: return unauthorized()

    val user = writableUser(authResult)
    user.email = email
    user.isEmailVerified = false

    val otp = EmailOtpService.issue(session, clientData.id)
    try {
      EmailOtpMailer.send(session, email, otp)
    } catch (e: EmailException) {
      logger.errorf(e, "Failed to send email-binding OTP for client »%s«", clientData.id)
      throw ErrorResponseException("email_send_failed", "Failed to send verification email", Response.Status.INTERNAL_SERVER_ERROR)
    }
    clientData.registrationStatus = ClientRegistrationStatus.OTP_PENDING
    logger.infof("Email-binding OTP (collect_email) issued for client »%s«", clientData.id)

    return Response.status(Response.Status.ACCEPTED).entity(mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP)).build()
  }

  @POST
  @Path(BIND_EMAIL_RESEND_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun resend(@FormParam("verify_type") verifyType: String?): Response {
    if (verifyType != null && verifyType != CHALLENGE_TYPE_EMAIL_OTP) {
      return Response.status(Response.Status.BAD_REQUEST).entity(mapOf("status" to "unsupported_verify_type")).build()
    }
    val authResult = authorize(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION) ?: return unauthorized()
    val clientData = loadMobileClientData(authResult) ?: return unauthorized()

    val email = authResult.user().email
    if (clientData.registrationStatus != ClientRegistrationStatus.OTP_PENDING || email.isNullOrBlank()) {
      return Response.status(Response.Status.CONFLICT).entity(mapOf("status" to "no_pending_challenge")).build()
    }

    val otp = EmailOtpService.issue(session, clientData.id)
    try {
      EmailOtpMailer.send(session, email, otp)
    } catch (e: EmailException) {
      logger.errorf(e, "Failed to send email-binding OTP for client »%s«", clientData.id)
      throw ErrorResponseException("email_send_failed", "Failed to send verification email", Response.Status.INTERNAL_SERVER_ERROR)
    }
    logger.infof("Email-binding OTP (resend) issued for client »%s«", clientData.id)

    return Response.status(Response.Status.ACCEPTED)
        .entity(mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to maskEmail(email)))
        .build()
  }

  /** verify_otp: check the OTP; on success mark the email verified and the client bound. */
  @POST
  @Path(BIND_EMAIL_VERIFY_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun verify(@FormParam("code") code: String?, @FormParam("verify_type") verifyType: String?): Response {
    if (verifyType != null && verifyType != CHALLENGE_TYPE_EMAIL_OTP) {
      return Response.status(Response.Status.BAD_REQUEST).entity(mapOf("status" to "unsupported_verify_type")).build()
    }
    val authResult = authorize(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION) ?: return unauthorized()
    val clientData = loadMobileClientData(authResult) ?: return unauthorized()

    if (!EmailOtpService.verify(session, clientData.id, code)) {
      return Response.status(Response.Status.BAD_REQUEST).entity(mapOf("status" to "invalid_code")).build()
    }

    writableUser(authResult).isEmailVerified = true
    clientData.registrationStatus = ClientRegistrationStatus.CONFIRMED
    logger.infof("Email binding verified for client »%s« → bound", clientData.id)

    return Response.ok(mapOf("status" to "bound")).build()
  }

  /** Sub-resource locator for the client-management endpoint `POST zeta/identity/email` (spec path, A_29911/A_30101). */
  @Path(IDENTITY_EMAIL_PATH)
  fun identityEmail(): EmailChangeResource = EmailChangeResource(session)

  @Path(USERINFO_EMAIL_PATH)
  fun userInfoEmail(): UserInfoEmailResource = UserInfoEmailResource()

  /** Authenticate the bearer token and require [requiredScope]. */
  private fun authorize(requiredScope: String): AuthenticationManager.AuthResult? {
    val authResult = AppAuthManager.BearerTokenAuthenticator(session).authenticate() ?: return null

    val scopes = authResult.token().scope?.split(' ')?.toSet().orEmpty()
    if (requiredScope !in scopes) {
      logger.warnf("email-binding endpoint rejected: token lacks scope »%s« (scopes: %s)", requiredScope, scopes)
      return null
    }
    return authResult
  }

  private fun loadMobileClientData(authResult: AuthenticationManager.AuthResult): ZetaGuardClientData? {
    val clientId = authResult.client()?.clientId ?: return null
    val clientData = ZetaGuardDataService(DefaultEMCreator(session)).findClientData(clientId) ?: return null
    return clientData.takeIf { it.clientAuthMethod == ClientAuthMethod.SEK_IDP }
  }

  /** A CachedUserModel must be unwrapped for writes to persist (see SekIDPIdentityProvider.updateBrokeredUser). */
  private fun writableUser(authResult: AuthenticationManager.AuthResult): UserModel =
      (authResult.user() as? CachedUserModel)?.delegateForUpdate ?: authResult.user()

  private fun unauthorized(): Response =
      Response.status(Response.Status.UNAUTHORIZED).entity(mapOf("status" to "unauthorized")).build()

  override fun close() {
    // No-op
  }
}
