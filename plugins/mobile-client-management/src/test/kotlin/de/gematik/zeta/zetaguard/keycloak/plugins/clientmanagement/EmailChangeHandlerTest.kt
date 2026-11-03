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

import de.gematik.zeta.zetaguard.keycloak.commons.email.EMAIL_OTP_STORE_PREFIX
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPService
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_USER
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaActor
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.logZetaAdminEvent
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_PENDING_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.MEDIA_TYPE_PROBLEM_JSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import de.gematik.zeta.zetaguard.keycloak.plugins.revocation.revokeClientSessions
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import jakarta.ws.rs.core.Response
import org.keycloak.email.EmailException
import org.keycloak.events.Details
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientProvider
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.SingleUseObjectProvider
import org.keycloak.models.UserModel
import org.keycloak.models.UserProvider
import org.keycloak.services.ErrorResponseException

private const val CALLER_ID = "caller-client"
private const val USER_NAME = "spicy-hash-of-kvnr"
private const val OLD_EMAIL = "old@example.de"
private const val NEW_EMAIL = "new@example.de"
private const val OTP = "123456"
private const val USER_ID = "user-uuid"
private const val ZETA_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEventsKt"
private const val ZETA_ADMIN_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaAdminEventsKt"

private fun body(newEmail: String? = NEW_EMAIL, stepUp: String? = null): EmailChangeRequest =
    EmailChangeRequest().apply {
      this.newEmail = newEmail
      idpStepUp = stepUp
    }

@Suppress("UNCHECKED_CAST") //
private fun Response.entityMap(): Map<String, Any> = entity as Map<String, Any>

class EmailChangeHandlerTest :
  StringSpec({
    lateinit var userData: ZetaGuardUserData
    lateinit var callerData: ZetaGuardClientData
    lateinit var user: UserModel
    lateinit var realm: RealmModel
    lateinit var clients: ClientProvider
    lateinit var singleUse: SingleUseObjectProvider
    lateinit var session: KeycloakSession
    lateinit var dataService: ZetaGuardDataService

    fun clientData(id: String, status: ClientRegistrationStatus?, authMethod: ClientAuthMethod = ClientAuthMethod.SEK_IDP): ZetaGuardClientData =
        ZetaGuardClientData(id, currentTime(), currentTime()).also {
          it.clientAuthMethod = authMethod
          it.registrationStatus = status
          it.attestationState = ClientAttestationState.VALID
          it.userData = userData
          userData.clients.add(it)
        }

    beforeTest {
      userData = ZetaGuardUserData(USER_NAME, currentTime(), currentTime())
      callerData = clientData(CALLER_ID, ClientRegistrationStatus.CONFIRMED)

      user =
          mockk<UserModel>(relaxed = true) {
            every { id } returns USER_ID
            every { username } returns USER_NAME
            every { email } returns OLD_EMAIL
            every { isEmailVerified } returns true
          }
      realm = mockk<RealmModel>(relaxed = true)
      clients = mockk<ClientProvider> { every { removeClient(any(), any()) } returns true }
      singleUse = mockk<SingleUseObjectProvider>(relaxed = true)

      val users = mockk<UserProvider> { every { getUserByUsername(realm, USER_NAME) } returns user }
      val keycloakContext = mockk<KeycloakContext>()
      every { keycloakContext.realm } returns realm
      every { keycloakContext.connection } returns null
      session =
          mockk<KeycloakSession> {
            every { context } returns keycloakContext
            every { users() } returns users
            every { clients() } returns clients
            every { singleUseObjects() } returns singleUse
          }
      dataService =
          mockk<ZetaGuardDataService> {
            every { findClientData(CALLER_ID) } returns callerData
            justRun { deleteClientData(any()) }
          }

      mockkObject(EmailOTPService, EmailOTPMailer)
      mockkObject(SecurityEventLogger)
      mockkStatic(ZETA_EVENTS)
      mockkStatic(ZETA_ADMIN_EVENTS)
      justRun { logZetaAdminEvent(any(), any(), any(), any(), any(), any()) }
      justRun { fireZetaEvent(any(), any(), any(), any(), any(), any(), any()) }
      justRun { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      every { EmailOTPService.issue(session, CALLER_ID) } returns OTP
      justRun { EmailOTPMailer.send(any(), any(), any()) }
    }

    afterTest { unmockkAll() }

    fun handler() = EmailChangeHandler(session, dataService)

    "a missing body yields 400 invalidRequest as problem+json" {
      val response = handler().handle(callerData, null)

      response.status shouldBe 400
      response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
      response.entityMap()["code"] shouldBe ProblemCodes.INVALID_REQUEST
    }

    "an invalid email address yields 400 invalidRequest" {
      val response = handler().handle(callerData, body(newEmail = "not-an-email"))

      response.status shouldBe 400
      response.entityMap()["code"] shouldBe ProblemCodes.INVALID_REQUEST
    }

    "the new address is remembered as pending and the code goes to the new address, the stored address is untouched" {
      val response = handler().handle(callerData, body())

      response.status shouldBe 202
      response.entityMap() shouldBe mapOf("status" to "pending", "challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to "n*@e*.de")
      verify { user.setSingleAttribute(ATTRIBUTE_USER_PENDING_EMAIL, NEW_EMAIL) }
      verify { EmailOTPMailer.send(session, NEW_EMAIL, OTP) }
      verify(exactly = 0) { user.email = any() }
      verify(exactly = 0) { user.isEmailVerified = any() }
      verify(exactly = 0) { fireZetaEvent(any(), any(), any(), any(), any(), any(), any()) }
      verify(exactly = 0) { dataService.deleteClientData(any()) }
    }

    "a mail failure yields 500 and leaves nothing pending" {
      every { EmailOTPMailer.send(any(), any(), any()) } throws EmailException("smtp down")

      shouldThrow<ErrorResponseException> { handler().handle(callerData, body()) }

      verify(exactly = 0) { user.setSingleAttribute(any(), any<String>()) }
    }

    "changing to the current verified address is an idempotent no-op" {
      val response = handler().handle(callerData, body(newEmail = OLD_EMAIL.uppercase()))

      response.status shouldBe 202
      response.entityMap() shouldBe mapOf("status" to "verified")
      verify(exactly = 0) { EmailOTPService.issue(any(), any()) }
      verify(exactly = 0) { user.setSingleAttribute(any(), any<String>()) }
    }

    "a supplied idp_step_up is accepted and ignored" {
      val response = handler().handle(callerData, body(stepUp = "some-step-up-token"))

      response.status shouldBe 202
      verify { EmailOTPMailer.send(session, NEW_EMAIL, OTP) }
    }

    "completing the change sets the address identity-wide and informs the old address" {
      handler().completeChange(callerData, user, NEW_EMAIL)

      verify { user.email = NEW_EMAIL }
      verify { user.isEmailVerified = true }
      verify { user.removeAttribute(ATTRIBUTE_USER_PENDING_EMAIL) }
      verify { fireZetaEvent(session, realm, ZetaEvent.EMAIL_CHANGED, USER_ID, details = mapOf(Details.PREVIOUS_EMAIL to OLD_EMAIL)) }
      verify {
        logZetaAdminEvent(
            session,
            realm,
            ZetaEvent.EMAIL_CHANGED,
            "users/$USER_ID",
            match<ZetaActor> { it.userId == USER_ID },
            mapOf(DETAIL_ZETA_USER to USER_NAME),
        )
      }
    }

    "completing the change deletes siblings with a pending OTP challenge and keeps the others" {
      clientData("sibling-pending", ClientRegistrationStatus.OTP_PENDING)
      clientData("sibling-verified", ClientRegistrationStatus.CONFIRMED)
      val pendingSiblingModel =
          mockk<ClientModel> {
            every { id } returns "internal-sibling-pending"
            every { name } returns "Old phone"
          }
      every { realm.getClientByClientId("sibling-pending") } returns pendingSiblingModel
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.revocation.SessionRevocationKt")
      every { revokeClientSessions(session, realm, pendingSiblingModel) } returns listOf("sid-1")

      handler().completeChange(callerData, user, NEW_EMAIL)

      verify { revokeClientSessions(session, realm, pendingSiblingModel) }
      verify { clients.removeClient(realm, "internal-sibling-pending") }
      verify { dataService.deleteClientData("sibling-pending") }
      verify { singleUse.remove(EMAIL_OTP_STORE_PREFIX + "sibling-pending") }
      verify(exactly = 0) { dataService.deleteClientData("sibling-verified") }
      verify(exactly = 0) { dataService.deleteClientData(CALLER_ID) }
      verify(exactly = 1) { fireClientRemoved(session, realm, USER_ID, any(), any(), any()) }
      verify { fireClientRemoved(session, realm, USER_ID, "sibling-pending", "Old phone", ClientRemovalReason.EMAIL_CHANGE_PENDING) }
      verify { SecurityEventLogger.logClientDeleted("sibling-pending", "email_change_pending") }
      verify(exactly = 0) { SecurityEventLogger.logClientDeleted("sibling-verified", any()) }
    }

    "completing the change does not inform the old address when it equals the new one" {
      handler().completeChange(callerData, user, OLD_EMAIL.uppercase())

      verify(exactly = 0) { fireZetaEvent(any(), any(), ZetaEvent.EMAIL_CHANGED, any(), any(), any(), any()) }
    }
  })
