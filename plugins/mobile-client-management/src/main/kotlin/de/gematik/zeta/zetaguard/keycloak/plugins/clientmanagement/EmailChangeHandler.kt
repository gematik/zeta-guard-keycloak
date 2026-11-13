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

import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPService
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_USER
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaActor
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.logZetaAdminEvent
import de.gematik.zeta.zetaguard.keycloak.commons.maskEmail
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_PENDING_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_STATUS_PENDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_STATUS_VERIFIED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.problem
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import de.gematik.zeta.zetaguard.keycloak.plugins.revocation.revokeClientSessions
import de.gematik.zeta.zetaguard.keycloak.plugins.toWritableUser
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.email.EmailException
import org.keycloak.events.Details
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.validation.Validation

private val logger: Logger = Logger.getLogger(EmailChangeHandler::class.java)

class EmailChangeHandler(
    private val session: KeycloakSession,
    private val dataService: ZetaGuardDataService,
) {

  /**
   * Domain checks and the challenge — [clientData] is already authenticated and checked by the HTTP layer
   * ([EmailChangeResource], via [PepClientDataService]).
   *
   * The address is only remembered as pending and a one-time code goes to the NEW address; the stored address stays
   * verified until the code is confirmed (A_29911/A_29912).
   */
  fun handle(clientData: ZetaGuardClientData, request: EmailChangeRequest?): Response = either {
    ensure(request != null) { requestProblem("Request body required") }

    val newEmail = request.newEmail?.trim()

    ensure(!newEmail.isNullOrBlank() && Validation.isEmailValid(newEmail)) { requestProblem("»new_email« must be a valid email address") }

    val userData = clientData.userData ?: raise(authorizationProblem("Client is not bound to an identity"))

    val realm = session.context.realm
    val user = session.users().getUserByUsername(realm, userData.id) ?: raise(authorizationProblem("Identity not found"))

    if (request.idpStepUp != null) {
      // A_29911: step-up proof accepted but not evaluated, no 401 insufficient_user_authentication
      logger.debugf("idp_step_up supplied by client »%s« — accepted but not evaluated", clientData.id)
    }

    if (newEmail.equals(user.email, ignoreCase = true) && user.isEmailVerified) {
      // idempotent no-op, nothing changed, no challenge
      return Response.status(Response.Status.ACCEPTED).entity(mapOf("status" to EMAIL_STATUS_VERIFIED)).build()
    }

    val otp = EmailOTPService.issue(session, clientData.id, newEmail)
    try {
      EmailOTPMailer.send(session, newEmail, otp)
    } catch (e: EmailException) {
      logger.errorf(e, "Failed to send email-change OTP for client »%s«", clientData.id)
      throw ErrorResponseException("email_send_failed", "Failed to send verification email", Response.Status.INTERNAL_SERVER_ERROR)
    }

    user.toWritableUser().setSingleAttribute(ATTRIBUTE_USER_PENDING_EMAIL, newEmail)

    logger.infof("Email-change OTP issued for client »%s«", clientData.id)
    Response.status(Response.Status.ACCEPTED)
        .entity(mapOf("status" to EMAIL_STATUS_PENDING, "challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to newEmail.maskEmail()))
        .build()
  }.getOrElse { it }

  /**
   * Completes a pending change after the OTP sent to the new address was confirmed: the address is set identity-wide,
   * siblings still waiting for a code sent to the old address are removed, and the old address is informed (A_25750).
   */
  fun completeChange(clientData: ZetaGuardClientData, user: UserModel, newEmail: String) {
    val realm = session.context.realm
    val oldEmail = user.email

    user.toWritableUser().apply {
      email = newEmail
      isEmailVerified = true
      removeAttribute(ATTRIBUTE_USER_PENDING_EMAIL)
    }

    val pendingSiblingIds = clientData.userData?.let { updateSiblings(it, clientData, user, realm) }.orEmpty()

    if (!oldEmail.isNullOrBlank() && !oldEmail.equals(newEmail, ignoreCase = true)) {
      fireZetaEvent(session, realm, ZetaEvent.EMAIL_CHANGED, user.id, details = mapOf(Details.PREVIOUS_EMAIL to oldEmail))
    }
    logZetaAdminEvent(
        session,
        realm,
        ZetaEvent.EMAIL_CHANGED,
        "users/${user.id}",
        ZetaActor(user.id, realm.getClientByClientId(clientData.id)?.id, session.context.connection?.remoteHost),
        mapOf(DETAIL_ZETA_USER to user.username),
    )

    SecurityEventLogger.logEmailChanged(clientId = clientData.id)
    logger.infof("Identity email changed by client »%s«; removed %d sibling(s) with a pending OTP challenge", clientData.id, pendingSiblingIds.size)
  }

  private fun updateSiblings(userData: ZetaGuardUserData, clientData: ZetaGuardClientData, user: UserModel, realm: RealmModel): List<String> {
    val pendingSiblingIds = userData.clients
        .filter { it.id != clientData.id && it.registrationStatus == ClientRegistrationStatus.OTP_PENDING }
        .map { it.id }

    pendingSiblingIds.forEach { siblingId ->
      EmailOTPService.invalidate(session, siblingId) // drop the open challenge for the old address
      val sibling = realm.getClientByClientId(siblingId)
      sibling?.let {
        revokeClientSessions(session, realm, it) // their binding tokens are short-lived, but the sessions would outlive the client
        session.clients().removeClient(realm, it.id)
      }

      dataService.deleteClientData(siblingId)
      SecurityEventLogger.logClientDeleted(clientId = siblingId, reason = ClientRemovalReason.EMAIL_CHANGE_PENDING.value)
      fireClientRemoved(session, realm, user.id, siblingId, sibling?.name, ClientRemovalReason.EMAIL_CHANGE_PENDING)
    }

    return pendingSiblingIds
  }

  private fun requestProblem(text: String): Response = problem(Response.Status.BAD_REQUEST, ProblemCodes.INVALID_REQUEST, text)

  private fun authorizationProblem(text: String) = problem(Response.Status.UNAUTHORIZED, ProblemCodes.UNAUTHORIZED, text)
}
