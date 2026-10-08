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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.email.EMAIL_OTP_STORE_PREFIX
import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_STATUS_VERIFIED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.problem
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailChangeNotifier
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.models.cache.CachedUserModel
import org.keycloak.services.validation.Validation

private val logger: Logger = Logger.getLogger(EmailChangeHandler::class.java)

class EmailChangeHandler(
    private val session: KeycloakSession,
    private val dataService: ZetaGuardDataService,
) {

  /** Domain checks and the change itself — [client] is already authenticated by the HTTP layer ([EmailChangeResource]). */
  fun handle(client: ClientModel, request: EmailChangeRequest?): Response {
    if (request == null) {
      return problem(Response.Status.BAD_REQUEST, ProblemCodes.INVALID_REQUEST, "Request body required")
    }
    val newEmail = request.newEmail?.trim()
    if (newEmail.isNullOrBlank() || !Validation.isEmailValid(newEmail)) {
      return problem(Response.Status.BAD_REQUEST, ProblemCodes.INVALID_REQUEST, "»new_email« must be a valid email address")
    }

    // A_29909: the email may only be managed by a registered, valid *mobile* client of the identity
    val (clientData, userData) = with(dataService.findClientData(client.clientId)) {
      when {
        this?.clientAuthMethod != ClientAuthMethod.SEK_IDP -> return problem(
            Response.Status.UNAUTHORIZED,
            ProblemCodes.FACTOR_REQUIRED,
            "Not a registered mobile client"
        )

        this.attestationState != ClientAttestationState.VALID -> return problem(
            Response.Status.UNAUTHORIZED,
            ProblemCodes.FACTOR_REQUIRED,
            "Client registration is not valid (attestation state)"
        )

        this.registrationStatus != ClientRegistrationStatus.CONFIRMED -> return problem(
            Response.Status.UNAUTHORIZED,
            ProblemCodes.FACTOR_REQUIRED,
            "Calling client's email binding (F1) is not confirmed"
        )

        this.userData == null -> return problem(
            Response.Status.UNAUTHORIZED,
            ProblemCodes.FACTOR_REQUIRED,
            "Client is not bound to an identity"
        )
      }
      this to this.userData!!
    }

    val realm = session.context.realm
    val user = session.users().getUserByUsername(realm, userData.id)
      ?: return problem(Response.Status.UNAUTHORIZED, ProblemCodes.FACTOR_REQUIRED, "Identity not found")

    if (request.idpStepUp != null) {
      // A_29911: step-up proof accepted but not evaluated, no 401 insufficient_user_authentication — not in scope MS5A
      logger.debugf("idp_step_up supplied by client »%s« — accepted but not evaluated", clientData.id)
    }

    val oldEmail = user.email
    if (newEmail.equals(oldEmail, ignoreCase = true)) {
      return accepted() // idempotent no-op, nothing changed, nobody is notified and no siblings are touched
    }

    writableUser(user).apply {
      email = newEmail
      // A_29911/A_29912: verified without OTP, old F1 should be kept until confirmed — not in scope MS5A
      isEmailVerified = true
    }

    // Open OTP challenges of sibling clients still target the old address — those registrations are removed
    val pendingSiblingIds =
        userData.clients.filter { it.id != clientData.id && it.registrationStatus == ClientRegistrationStatus.OTP_PENDING }.map { it.id }
    pendingSiblingIds.forEach { siblingId ->
      session.singleUseObjects().remove(EMAIL_OTP_STORE_PREFIX + siblingId) // drop the open challenge for the old address
      realm.getClientByClientId(siblingId)?.let { session.clients().removeClient(realm, it.id) }
      dataService.deleteClientData(siblingId)
    }

    // A_25750: the old address is the identity owner's primary chance to detect a hostile change (best effort)
    if (!oldEmail.isNullOrBlank()) {
      EmailChangeNotifier.notifyOldAddress(session, oldEmail)
    }

    SecurityEventLogger.logEmailChanged(clientId = clientData.id)
    logger.infof("Identity email changed by client »%s«; removed %d sibling(s) with a pending OTP challenge", clientData.id, pendingSiblingIds.size)

    return accepted()
  }

  /** EmailStatus shape of [zeta-guard-client-management]; `transaction_id` + `status=pending` join additively with the verify step. */
  private fun accepted(): Response = Response.status(Response.Status.ACCEPTED).entity(mapOf("status" to EMAIL_STATUS_VERIFIED)).build()

  /** A CachedUserModel must be unwrapped for writes to persist (see SekIDPIdentityProvider.updateBrokeredUser). */
  private fun writableUser(user: UserModel): UserModel = (user as? CachedUserModel)?.delegateForUpdate ?: user
}
