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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.MEDIA_TYPE_PROBLEM_JSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailChangeNotifier
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkAll
import io.mockk.verify
import jakarta.ws.rs.core.Response
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientProvider
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.SingleUseObjectProvider
import org.keycloak.models.UserModel
import org.keycloak.models.UserProvider

private const val CALLER_ID = "caller-client"
private const val USER_NAME = "spicy-hash-of-kvnr"
private const val OLD_EMAIL = "old@example.de"
private const val NEW_EMAIL = "new@example.de"

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
      lateinit var callerModel: ClientModel

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
              every { email } returns OLD_EMAIL
            }
        realm = mockk<RealmModel>(relaxed = true)
        clients = mockk<ClientProvider> { every { removeClient(any(), any()) } returns true }
        singleUse = mockk<SingleUseObjectProvider>(relaxed = true)
        callerModel = mockk<ClientModel> { every { clientId } returns CALLER_ID }

        val users = mockk<UserProvider> { every { getUserByUsername(realm, USER_NAME) } returns user }
        val keycloakContext = mockk<KeycloakContext>()
        every { keycloakContext.realm } returns realm
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

        mockkObject(EmailChangeNotifier)
        justRun { EmailChangeNotifier.notifyOldAddress(any(), any()) }
      }

      afterTest { unmockkAll() }

      fun handler() = EmailChangeHandler(session, dataService)

      "a missing body yields 400 invalidRequest as problem+json" {
        val response = handler().handle(callerModel, null)

        response.status shouldBe 400
        response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
        response.entityMap()["code"] shouldBe ProblemCodes.INVALID_REQUEST
      }

      "an invalid email address yields 400 invalidRequest" {
        val response = handler().handle(callerModel, body(newEmail = "not-an-email"))

        response.status shouldBe 400
        response.entityMap()["code"] shouldBe ProblemCodes.INVALID_REQUEST
      }

      "a non-mobile caller yields 401 factorRequired (A_29909)" {
        callerData.clientAuthMethod = ClientAuthMethod.SMC_B

        val response = handler().handle(callerModel, body())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.FACTOR_REQUIRED
      }

      "a caller whose registration is not VALID yields 401 factorRequired" {
        callerData.attestationState = ClientAttestationState.PENDING

        val response = handler().handle(callerModel, body())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.FACTOR_REQUIRED
      }

      "a caller without verified email binding yields 401 factorRequired" {
        callerData.registrationStatus = ClientRegistrationStatus.OTP_PENDING

        val response = handler().handle(callerModel, body())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.FACTOR_REQUIRED
      }

      "the email is changed identity-wide and 202 with status=verified is returned" {
        val response = handler().handle(callerModel, body())

        response.status shouldBe 202
        response.entityMap() shouldBe mapOf("status" to "verified")
        verify { user.email = NEW_EMAIL }
        verify { user.isEmailVerified = true }
        verify { EmailChangeNotifier.notifyOldAddress(session, OLD_EMAIL) }
      }

      "siblings with a pending OTP challenge are deleted, others are kept" {
        clientData("sibling-pending", ClientRegistrationStatus.OTP_PENDING)
        clientData("sibling-verified", ClientRegistrationStatus.CONFIRMED)
        val pendingSiblingModel = mockk<ClientModel> { every { id } returns "internal-sibling-pending" }
        every { realm.getClientByClientId("sibling-pending") } returns pendingSiblingModel

        val response = handler().handle(callerModel, body())

        response.status shouldBe 202
        verify { clients.removeClient(realm, "internal-sibling-pending") }
        verify { dataService.deleteClientData("sibling-pending") }
        verify { singleUse.remove(EMAIL_OTP_STORE_PREFIX + "sibling-pending") }
        verify(exactly = 0) { dataService.deleteClientData("sibling-verified") }
        verify(exactly = 0) { dataService.deleteClientData(CALLER_ID) }
      }

      "changing to the same address is an idempotent no-op" {
        clientData("sibling-pending", ClientRegistrationStatus.OTP_PENDING)

        val response = handler().handle(callerModel, body(newEmail = OLD_EMAIL.uppercase()))

        response.status shouldBe 202
        response.entityMap() shouldBe mapOf("status" to "verified")
        verify(exactly = 0) { user.email = any() }
        verify(exactly = 0) { dataService.deleteClientData(any()) }
        verify(exactly = 0) { EmailChangeNotifier.notifyOldAddress(any(), any()) }
      }

      "a supplied idp_step_up is accepted and ignored in this Stufe" {
        val response = handler().handle(callerModel, body(stepUp = "some-step-up-token"))

        response.status shouldBe 202
        verify { user.email = NEW_EMAIL }
      }
    })
