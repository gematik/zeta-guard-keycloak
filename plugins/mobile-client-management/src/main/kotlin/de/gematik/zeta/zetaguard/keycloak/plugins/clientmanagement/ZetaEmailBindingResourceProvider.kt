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

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import com.fasterxml.jackson.annotation.JsonProperty
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPService
import de.gematik.zeta.zetaguard.keycloak.commons.email.verifiedEmail
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_TARGET_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_USER
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaActor
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.logZetaAdminEvent
import de.gematik.zeta.zetaguard.keycloak.commons.maskEmail
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_PENDING_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_RESEND_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_VERIFY_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLIENTS_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLIENT_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_STATUS_VERIFIED
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_RESEND_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_VERIFY_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.USERINFO_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.problem
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.ResourceServerCertificateValidator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo.UserInfoEmailResource
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.toWritableUser
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import de.gematik.zeta.zetaguard.keycloak.plugins.revocation.revokeClientSessions
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.FormParam
import jakarta.ws.rs.GET
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status
import jakarta.ws.rs.core.Response.Status.ACCEPTED
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import jakarta.ws.rs.core.Response.Status.CONFLICT
import jakarta.ws.rs.core.Response.Status.INTERNAL_SERVER_ERROR
import jakarta.ws.rs.core.Response.Status.NOT_FOUND
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.resource.RealmResourceProvider

private val logger: Logger = Logger.getLogger(ZetaEmailBindingResourceProvider::class.java)

data class ClientRep(
    @JsonProperty("client_id") val clientId: String, val name: String?
)

class ZetaEmailBindingResourceProvider(
    internal val session: KeycloakSession,
    private val resourceServerValidator: ResourceServerCertificateValidator = ResourceServerCertificateValidator(emptySet()),
) : RealmResourceProvider {

  override fun getResource(): Any = this

  private val dataService = ZetaGuardDataService(DefaultEMCreator(session))
  private val pepClientDataService = PepClientDataService(dataService)

  private fun mkProblem(
      title: String,
      detail: String? = null,
      code: String = ProblemCodes.UNAUTHORIZED,
      status: Status = Status.UNAUTHORIZED,
      logLevel: Logger.Level = Logger.Level.DEBUG,
  ) = problem(status, code, title, detail).also { logger.log(logLevel, title) }

  private fun ZetaGuardUserData.mobileClients() = clients.filter { it.clientAuthMethod == ClientAuthMethod.SEK_IDP }

  @GET
  @Path(CLIENTS_PATH)
  @Produces(MediaType.APPLICATION_JSON)
  fun listClients(@HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?): Response = session.problemOnError {
    val user = pepClientDataService.userFromPep(zetaClientData).mapLeft(::mkProblem).getOrElse { return it }

    val clients =
        user.mobileClients().mapNotNull { client ->
          val kclient =
              session.clients().getClientByClientId(session.context.realm, client.id)
                ?: return@mapNotNull null.also { logger.warn("keycloak client »${client.id}« not found, skipping") }
          ClientRep(clientId = client.id, name = kclient.name)
        }
    Response.ok(clients).build()
  }

  @Suppress("UnresolvedRestParam")
  @DELETE
  @Path(CLIENT_PATH)
  @Produces(MediaType.APPLICATION_JSON)
  fun deleteClient(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @PathParam("id") id: String,
  ): Response = session.problemOnError {
    val (caller, user) = pepClientDataService.callerFromPep(zetaClientData).mapLeft(::mkProblem).getOrElse { return it }

    val client =
        user.mobileClients().singleOrNull { it.id == id }
          ?: return mkProblem("zeta client »$id« not found", code = ProblemCodes.NOT_FOUND, status = NOT_FOUND)

    val realm = session.context.realm
    val kclient = session.clients().getClientByClientId(realm, client.id)
    // the actor of the admin event, looked up before a client deleting itself is gone
    val callerKeycloakId = session.clients().getClientByClientId(realm, caller.id)?.id

    if (kclient == null) {
      logger.warn("keycloak client »${client.id}« not found, skipping")
    } else {
      // before the removal: the sessions are looked up by client
      val revoked = revokeClientSessions(session, realm, kclient)
      logger.debug("revoked sessions »$revoked« of keycloak client »${kclient.id}«")

      if (session.clients().removeClient(realm, kclient.id)) {
        logger.debug("deleted keycloak client »${kclient.id}«")
      } else {
        logger.warn("keycloak client »${kclient.id}« unexpectedly not deleted")
      }
    }

    logger.debug("deleting zeta client »${client.id}«")
    dataService.deleteClientData(client.id)
    EmailOTPService.invalidate(session, client.id)
    SecurityEventLogger.logClientDeleted(clientId = client.id, reason = ClientRemovalReason.USER_REQUEST.value)

    // without a Keycloak user there is no address to notify, but the call is still logged
    val keycloakUser = session.users().getUserByUsername(realm, user.id)
    keycloakUser?.let { fireClientRemoved(session, realm, it.id, client.id, kclient?.name, ClientRemovalReason.USER_REQUEST) }
    logZetaAdminEvent(
        session,
        realm,
        ZetaEvent.CLIENT_REMOVED,
        "clients/${kclient?.id ?: client.id}",
        ZetaActor(keycloakUser?.id, callerKeycloakId, session.context.connection?.remoteHost),
        mapOf(DETAIL_ZETA_TARGET_CLIENT_ID to client.id, DETAIL_ZETA_USER to user.id),
    )

    Response.noContent().build()
  }

  /** collect_email: store the submitted email, generate + "send" (stub) an OTP, move → OTP_PENDING. */
  @POST
  @Path(BIND_EMAIL_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun bindEmail(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @FormParam("email") email: String?,
  ): Response =
      collectEmail(zetaClientData, email).getOrElse {
        Response.status(it.statusCode).entity(mapOf("status" to it.error)).build()
      }

  @POST
  @Path(BIND_EMAIL_RESEND_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun resend(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @FormParam("verify_type") verifyType: String?,
  ): Response =
      resendEmail(authorizeRegistration(zetaClientData, verifyType)).getOrElse {
        Response.status(it.statusCode).entity(mapOf("status" to it.error)).build()
      }

  /** verify_otp: check the OTP; on success mark the email verified and the client bound. */
  @POST
  @Path(BIND_EMAIL_VERIFY_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun verify(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @FormParam("code") code: String?,
      @FormParam("verify_type") verifyType: String?,
  ): Response =
      verifyOTP(authorizeRegistration(zetaClientData, verifyType), code).getOrElse {
        Response.status(it.statusCode).entity(mapOf("status" to it.error)).build()
      }

  /** Sub-resource locator for the client-management endpoint `POST zeta/identity/email` (spec path, A_29911). */
  @Path(IDENTITY_EMAIL_PATH)
  fun identityEmail(): EmailChangeResource = EmailChangeResource(session)

  /** Completes a pending email change (spec path, behind the PEP); the registration challenge stays on [BIND_EMAIL_VERIFY_PATH]. */
  @POST
  @Path(IDENTITY_EMAIL_VERIFY_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun verifyEmailChange(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @FormParam("code") code: String?,
      @FormParam("verify_type") verifyType: String?,
  ): Response = session.problemOnError {
    verifyOTP(authorizeEmailChange(zetaClientData, verifyType), code).getOrElse {
      it.toProblem()
    }
  }

  @POST
  @Path(IDENTITY_EMAIL_RESEND_PATH)
  @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
  @Produces(MediaType.APPLICATION_JSON)
  fun resendEmailChange(
      @HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?,
      @FormParam("verify_type") verifyType: String?,
  ): Response = session.problemOnError {
    resendEmail(authorizeEmailChange(zetaClientData, verifyType)).getOrElse {
      it.toProblem()
    }
  }

  /** Sub-resource locator for `GET zeta/userinfo/email`, called by resource servers authenticating via mTLS. */
  @Path(USERINFO_EMAIL_PATH)
  fun userInfoEmail(): UserInfoEmailResource = UserInfoEmailResource(session, resourceServerValidator)

  /**
   * The open challenge of the caller: a registration awaiting its code, or an identity-wide email change awaiting the code sent to the new address.
   */
  private sealed interface Challenge {
    data object Registration : Challenge

    data class EmailChange(val newEmail: String) : Challenge
  }

  private data class Authorized(
      val user: UserModel,
      val clientData: ZetaGuardClientData,
      val challenge: Challenge,
  )

  private fun checkVerifyType(verifyType: String?): Either<KeycloakError, Unit> = either {
    ensure(verifyType == null || verifyType == CHALLENGE_TYPE_EMAIL_OTP) {
      KeycloakError(
          "unsupported_verify_type",
          "unsupported_verify_type",
          BAD_REQUEST,
      )
    }
  }

  /**
   * Registration (`bind-email` paths): reachable only through the PEP, which verified the reduced binding token (scope
   * `zeta:email-verify`), its DPoP proof and forwards the client data; the caller is its `client_id` and is not confirmed yet.
   */
  private fun authorizeRegistration(zetaClientData: String?, verifyType: String?): Either<KeycloakError, Authorized> = either {
    checkVerifyType(verifyType).bind()

    val (user, clientData) = registeringCaller(zetaClientData).bind()

    Authorized(user, clientData, Challenge.Registration)
  }

  /** The client behind the PEP header together with the user it is bound to; the client need not be confirmed. */
  private fun registeringCaller(zetaClientData: String?): Either<KeycloakError, Pair<UserModel, ZetaGuardClientData>> = either {
    val clientData = pepClientDataService.clientFromPep(zetaClientData, requireConfirmed = false).mapLeft { unauthorized() }.bind()
    val userName = clientData.userData?.id ?: raise(unauthorized())
    val user = session.users().getUserByUsername(session.context.realm, userName) ?: raise(unauthorized())

    user to clientData
  }

  /**
   * Email change (`identity/email` paths): reachable only through the PEP, which verified token, DPoP and scope and forwards the client data; the
   * caller is its `client_id`. Without a pending change for the identity there is nothing to confirm.
   */
  private fun authorizeEmailChange(
      zetaClientData: String?,
      verifyType: String?,
  ): Either<KeycloakError, Authorized> = either {
    checkVerifyType(verifyType).bind()

    val clientData = pepClientDataService.clientFromPep(zetaClientData).mapLeft { unauthorized() }.bind()

    val userName = clientData.userData?.id?.takeIf { clientData.registrationStatus == ClientRegistrationStatus.CONFIRMED } ?: raise(unauthorized())
    val user = session.users().getUserByUsername(session.context.realm, userName) ?: raise(unauthorized())
    val newEmail =
        user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL)?.takeIf { it.isNotBlank() }
          ?: raise(KeycloakError("no_pending_challenge", "no_pending_challenge", CONFLICT))

    Authorized(user, clientData, Challenge.EmailChange(newEmail))
  }

  private fun verifyOTP(
      authorized: Either<KeycloakError, Authorized>,
      code: String?,
  ): Either<KeycloakError, Response> = either {
    val (user, clientData, challenge) = authorized.bind()
    // the address the code is about to confirm
    val email =
        when (challenge) {
          is Challenge.EmailChange -> challenge.newEmail
          Challenge.Registration -> user.email
        }

    ensure(EmailOTPService.verify(session, clientData.id, code, email)) { KeycloakError("invalid_code", "invalid_code", BAD_REQUEST) }

    when (challenge) {
      is Challenge.EmailChange -> {
        EmailChangeHandler(session, dataService).completeChange(clientData, user, challenge.newEmail)
        Response.ok(mapOf("status" to EMAIL_STATUS_VERIFIED)).build()
      }

      Challenge.Registration -> {
        // a verified address before this binding means the identity already has a bound client (verify_otp instead of collect_email)
        val existingIdentity = user.isEmailVerified

        user.toWritableUser().isEmailVerified = true
        clientData.registrationStatus = ClientRegistrationStatus.CONFIRMED

        if (existingIdentity) {
          val realm = session.context.realm
          val kclient = session.clients().getClientByClientId(realm, clientData.id)
          fireZetaEvent(session, realm, ZetaEvent.CLIENT_ADDED, user.id, clientData.id, kclient?.name)
          logZetaAdminEvent(
              session,
              realm,
              ZetaEvent.CLIENT_ADDED,
              "clients/${kclient?.id ?: clientData.id}",
              ZetaActor(user.id, kclient?.id, session.context.connection?.remoteHost),
              mapOf(DETAIL_ZETA_TARGET_CLIENT_ID to clientData.id, DETAIL_ZETA_USER to user.username),
          )
        }

        logger.infof("Email binding verified for client »%s« → bound", clientData.id)

        Response.ok(mapOf("status" to "bound")).build()
      }
    }
  }

  private fun collectEmail(zetaClientData: String?, email: String?): Either<KeycloakError, Response> = either {
    ensure(!email.isNullOrBlank()) { KeycloakError("missing_email", "missing_email", BAD_REQUEST) }

    val (user, clientData) = registeringCaller(zetaClientData).bind()

    // a verified address is only changed by a confirmed client via identity/email
    ensure(user.verifiedEmail() == null) { KeycloakError("email_already_bound", "email_already_bound", CONFLICT) }

    user.toWritableUser().apply {
      this.email = email
      this.isEmailVerified = false
    }

    sendOTP(clientData, email).bind()

    clientData.registrationStatus = ClientRegistrationStatus.OTP_PENDING
    logger.infof("Email-binding OTP (collect_email) issued for client »%s«", clientData.id)

    Response.status(ACCEPTED).entity(mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP)).build()
  }

  private fun resendEmail(authorized: Either<KeycloakError, Authorized>): Either<KeycloakError, Response> = either {
    val (user, clientData, challenge) = authorized.bind()
    val email =
        when (challenge) {
          is Challenge.EmailChange -> challenge.newEmail
          Challenge.Registration -> user.email?.takeIf { clientData.registrationStatus == ClientRegistrationStatus.OTP_PENDING }
        }

    ensure(!email.isNullOrBlank()) { KeycloakError("no_pending_challenge", "no_pending_challenge", CONFLICT) }

    sendOTP(clientData, email).bind()

    logger.infof("Email-binding OTP (resend) issued for client »%s«", clientData.id)

    Response.status(ACCEPTED)
        .entity(
            mapOf(
                "challenge_type" to CHALLENGE_TYPE_EMAIL_OTP,
                "email_hint" to email.maskEmail(),
            )
        )
        .build()
  }

  private fun sendOTP(
      clientData: ZetaGuardClientData,
      email: String,
  ): Either<KeycloakError, Unit> =
      Either.catch {
        val otp = EmailOTPService.issue(session, clientData.id, email)

        EmailOTPMailer.send(session, email, otp)
      }
          .mapLeft {
            logger.errorf(it, "Failed to send email-binding OTP for client »%s«", clientData.id)
            throw ErrorResponseException(
                "email_send_failed",
                "Failed to send verification email",
                INTERNAL_SERVER_ERROR,
            )
          }

  private fun unauthorized() = KeycloakError("unauthorized", "unauthorized", Status.UNAUTHORIZED)

  /**
   * The e-mail change endpoints answer problem+json like the client endpoints; the registration endpoints (`bind-email`, its
   * `resend` and `verify`) keep their `{status}` body, which the SDK already parses. Error ids of the shared OTP mechanics are
   * mapped to problem codes here.
   */
  private fun KeycloakError.toProblem(): Response {
    val code =
        when (error) {
          "unauthorized" -> ProblemCodes.UNAUTHORIZED
          "invalid_code" -> ProblemCodes.INVALID_CODE
          "no_pending_challenge" -> ProblemCodes.NO_PENDING_CHALLENGE
          "unsupported_verify_type" -> ProblemCodes.UNSUPPORTED_VERIFY_TYPE
          else -> ProblemCodes.INVALID_REQUEST
        }
    return problem(status, code, errorDescription ?: error)
  }

  override fun close() {
    // No-op
  }
}
