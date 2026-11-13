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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_USER_PENDING_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.MediaTypes
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOTPService
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_USER
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.logZetaAdminEvent
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import java.util.Base64
import org.keycloak.models.RealmModel
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkConstructor
import io.mockk.mockkStatic
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import jakarta.ws.rs.core.Response
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.models.cache.CachedUserModel

private const val CLIENT_ID = "mobile-client"
private const val ZETA_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEventsKt"
private const val ZETA_ADMIN_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaAdminEventsKt"

class ZetaEmailBindingResourceProviderTest : FunSpec() {
  init {
    afterEach {
      unmockkConstructor(ZetaGuardDataService::class)
      unmockkConstructor(EmailChangeHandler::class)
      unmockkObject(EmailOTPService)
      unmockkObject(EmailOTPMailer)
      unmockkStatic(ZETA_EVENTS, ZETA_ADMIN_EVENTS)
    }

    test("bindEmail rejects missing email") {
      val response = ZetaEmailBindingResourceProvider(mockk()).bindEmail(null, null)
      response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "missing_email")
    }

    test("bindEmail stores email, issues OTP and moves registration to OTP_PENDING") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      mockkObject(EmailOTPMailer)
      every { EmailOTPService.issue(session, "mobile-client", "alice@example.de") } returns "654321"
      justRun { EmailOTPMailer.send(session, "alice@example.de", "654321") }

      val response = ZetaEmailBindingResourceProvider(session).bindEmail(header, "alice@example.de")

      response.status shouldBe Response.Status.ACCEPTED.statusCode
      response.entityAsMap() shouldContainExactly mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP)
      verify {
        user.email = "alice@example.de"
        user.isEmailVerified = false
        EmailOTPService.issue(session, CLIENT_ID, "alice@example.de")
        EmailOTPMailer.send(session, "alice@example.de", "654321")
      }
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
    }

    test("bindEmail rejects an identity that already has a verified email") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user =
          mockk<UserModel>(relaxed = true) {
            every { email } returns "alice@example.de"
            every { isEmailVerified } returns true
          }
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      mockkObject(EmailOTPMailer)

      val response = ZetaEmailBindingResourceProvider(session).bindEmail(header, "mallory@example.de")

      response.status shouldBe Response.Status.CONFLICT.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "email_already_bound")
      verify(exactly = 0) {
        user.email = any()
        user.isEmailVerified = any()
        EmailOTPService.issue(any(), any(), any())
        EmailOTPMailer.send(any(), any(), any())
      }
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
    }

    test("bindEmail writes through CachedUserModel.delegateForUpdate") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val delegate = mockk<UserModel>(relaxed = true)
      val cached = mockk<CachedUserModel>(relaxed = true)
      every { cached.delegateForUpdate } returns delegate
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      val header = authenticate(session, cached, clientData)
      mockkObject(EmailOTPService)
      mockkObject(EmailOTPMailer)
      every { EmailOTPService.issue(session, "mobile-client", "alice@example.de") } returns "654321"
      justRun { EmailOTPMailer.send(session, "alice@example.de", "654321") }

      ZetaEmailBindingResourceProvider(session).bindEmail(header, "alice@example.de")

      verify {
        cached.delegateForUpdate
        delegate.email = "alice@example.de"
        delegate.isEmailVerified = false
      }
      verify(exactly = 0) {
        cached.email = any()
        cached.isEmailVerified = any()
      }
    }

    test("resend requires OTP_PENDING and SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.email } returns "alice@example.de"
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      val header = authenticate(session, user, clientData)

      val response = ZetaEmailBindingResourceProvider(session).resend(header, CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.CONFLICT.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "no_pending_challenge")
    }

    test("resend re-issues OTP when registration is OTP_PENDING") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.email } returns "alice@example.de"
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      mockkObject(EmailOTPMailer)
      every { EmailOTPService.issue(session, "mobile-client", "alice@example.de") } returns "111222"
      justRun { EmailOTPMailer.send(session, "alice@example.de", "111222") }

      val response = ZetaEmailBindingResourceProvider(session).resend(header, null)

      response.status shouldBe Response.Status.ACCEPTED.statusCode
      response.entityAsMap() shouldContainExactly
          mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to "a*@e*.de")
      verify {
        EmailOTPService.issue(session, CLIENT_ID, "alice@example.de")
        EmailOTPMailer.send(session, "alice@example.de", "111222")
      }
    }

    test("verify marks user verified and registration CONFIRMED") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true) { every { email } returns "alice@example.de" }
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      // the code has to belong to the address the identity holds right now
      every { EmailOTPService.verify(session, "mobile-client", "123456", "alice@example.de") } returns true

      val response = ZetaEmailBindingResourceProvider(session).verify(header, "123456", CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.OK.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "bound")
      verify { user.isEmailVerified = true }
      clientData.registrationStatus shouldBe ClientRegistrationStatus.CONFIRMED
    }

    test("verify binds the first client of an identity without a client_added notification") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true) { every { isEmailVerified } returns false }
      val header = authenticate(session, user, mobileClientData(ClientRegistrationStatus.OTP_PENDING))
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, CLIENT_ID, "123456", any()) } returns true
      mockkStatic(ZETA_EVENTS, ZETA_ADMIN_EVENTS)

      ZetaEmailBindingResourceProvider(session).verify(header, "123456", CHALLENGE_TYPE_EMAIL_OTP).status shouldBe Response.Status.OK.statusCode

      verify(exactly = 0) { fireZetaEvent(any(), any(), any(), any(), any(), any(), any()) }
      verify(exactly = 0) { logZetaAdminEvent(any(), any(), any(), any(), any(), any()) }
    }

    test("verify of another client of an identity with a verified address notifies client_added (N1)") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user =
          mockk<UserModel>(relaxed = true) {
            every { id } returns "user-uuid"
            every { username } returns "spicy-hash-of-kvnr"
            every { isEmailVerified } returns true
          }
      val header = authenticate(session, user, mobileClientData(ClientRegistrationStatus.OTP_PENDING))
      every { session.clients().getClientByClientId(any(), CLIENT_ID) } returns mockk<ClientModel> {
        every { id } returns "internal-mobile-client"
        every { name } returns "New phone"
      }
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, CLIENT_ID, "123456", any()) } returns true
      mockkStatic(ZETA_EVENTS, ZETA_ADMIN_EVENTS)
      justRun { fireZetaEvent(any(), any(), any(), any(), any(), any(), any()) }
      justRun { logZetaAdminEvent(any(), any(), any(), any(), any(), any()) }

      ZetaEmailBindingResourceProvider(session).verify(header, "123456", CHALLENGE_TYPE_EMAIL_OTP).status shouldBe Response.Status.OK.statusCode

      verify { fireZetaEvent(session, any(), ZetaEvent.CLIENT_ADDED, "user-uuid", CLIENT_ID, "New phone", any()) }
      verify { logZetaAdminEvent(session, any(), ZetaEvent.CLIENT_ADDED, any(), any(), match { it[DETAIL_ZETA_USER] == "spicy-hash-of-kvnr" }) }
    }

    test("verify writes through CachedUserModel.delegateForUpdate") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val delegate = mockk<UserModel>(relaxed = true)
      val cached = mockk<CachedUserModel>(relaxed = true)
      every { cached.delegateForUpdate } returns delegate
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, cached, clientData)
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, "mobile-client", "123456", any()) } returns true

      ZetaEmailBindingResourceProvider(session).verify(header, "123456", null)

      verify {
        cached.delegateForUpdate
        delegate.isEmailVerified = true
      }
      verify(exactly = 0) { cached.isEmailVerified = any() }
    }

    test("verify rejects invalid OTP") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, "mobile-client", "000000", any()) } returns false

      val response = ZetaEmailBindingResourceProvider(session).verify(header, "000000", null)

      response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "invalid_code")
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
    }

    test("a pending registration ignores a pending email change of the identity and still binds") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true) { every { email } returns "alice@example.de" }
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns "new@example.de"
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      val header = authenticate(session, user, clientData)
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, "mobile-client", "123456", "alice@example.de") } returns true

      val response = ZetaEmailBindingResourceProvider(session).verify(header, "123456", null)

      response.status shouldBe Response.Status.OK.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "bound")
      clientData.registrationStatus shouldBe ClientRegistrationStatus.CONFIRMED
    }

    test("identity/email/verify completes the pending change of the client named by the PEP header") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true) { every { email } returns "alice@example.de" }
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns "new@example.de"
      val clientData = boundClientData()
      val header = pepCaller(session, "mobile-client", clientData, user)
      mockkObject(EmailOTPService)
      // the code has to belong to the pending address, not to the one still bound
      every { EmailOTPService.verify(session, "mobile-client", "123456", "new@example.de") } returns true
      mockkConstructor(EmailChangeHandler::class)
      justRun { anyConstructed<EmailChangeHandler>().completeChange(clientData, user, "new@example.de") }

      val response = ZetaEmailBindingResourceProvider(session).verifyEmailChange(header, "123456", CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.OK.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "verified")
      verify { anyConstructed<EmailChangeHandler>().completeChange(clientData, user, "new@example.de") }
      verify(exactly = 0) { user.isEmailVerified = any() }
    }

    test("identity/email/verify rejects a wrong code without touching the identity") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns "new@example.de"
      val header = pepCaller(session, "mobile-client", boundClientData(), user)
      mockkObject(EmailOTPService)
      every { EmailOTPService.verify(session, "mobile-client", "000000", any()) } returns false
      mockkConstructor(EmailChangeHandler::class)

      val response = ZetaEmailBindingResourceProvider(session).verifyEmailChange(header, "000000", null)

      response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      response.mediaType.toString() shouldBe MediaTypes.PROBLEM_JSON
      response.entityAsMap()["code"] shouldBe ProblemCodes.INVALID_CODE
      response.entityAsMap()["status"] shouldBe Response.Status.BAD_REQUEST.statusCode
      verify(exactly = 0) { anyConstructed<EmailChangeHandler>().completeChange(any(), any(), any()) }
    }

    test("identity/email/verify and /resend reject a caller without a pending change") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns null
      val header = pepCaller(session, "mobile-client", boundClientData(), user)
      mockkObject(EmailOTPService)

      val provider = ZetaEmailBindingResourceProvider(session)

      provider.verifyEmailChange(header, "123456", null).status shouldBe Response.Status.CONFLICT.statusCode
      provider.resendEmailChange(header, null).status shouldBe Response.Status.CONFLICT.statusCode
      verify(exactly = 0) { EmailOTPService.verify(any(), any(), any(), any()) }
    }

    test("identity/email/verify and /resend reject a request without the PEP header") {
      val session = mockk<KeycloakSession>(relaxed = true)
      mockkConstructor(ZetaGuardDataService::class)

      val provider = ZetaEmailBindingResourceProvider(session)

      provider.verifyEmailChange(null, "123456", null).status shouldBe Response.Status.UNAUTHORIZED.statusCode
      provider.resendEmailChange(null, null).status shouldBe Response.Status.UNAUTHORIZED.statusCode
      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().findClientData(any()) }
    }

    test("identity/email/verify rejects a client that is not bound yet") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns "new@example.de"
      val header = pepCaller(session, "mobile-client", mobileClientData(ClientRegistrationStatus.OTP_PENDING), user)

      ZetaEmailBindingResourceProvider(session).verifyEmailChange(header, "123456", null).status shouldBe Response.Status.UNAUTHORIZED.statusCode
    }

    test("identity/email/resend sends the code to the new address") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.getFirstAttribute(ATTRIBUTE_USER_PENDING_EMAIL) } returns "new@example.de"
      val header = pepCaller(session, "mobile-client", boundClientData(), user)
      mockkObject(EmailOTPService)
      mockkObject(EmailOTPMailer)
      every { EmailOTPService.issue(session, "mobile-client", "new@example.de") } returns "555666"
      justRun { EmailOTPMailer.send(session, "new@example.de", "555666") }

      val response = ZetaEmailBindingResourceProvider(session).resendEmailChange(header, CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.ACCEPTED.statusCode
      response.entityAsMap() shouldContainExactly mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to "n*@e*.de")
    }

    test("registration endpoints reject a request without the PEP header") {
      val session = mockk<KeycloakSession>(relaxed = true)
      mockkConstructor(ZetaGuardDataService::class)

      val provider = ZetaEmailBindingResourceProvider(session)

      provider.bindEmail(null, "alice@example.de").status shouldBe Response.Status.UNAUTHORIZED.statusCode
      provider.resend(null, null).status shouldBe Response.Status.UNAUTHORIZED.statusCode
      provider.verify(null, "123456", null).status shouldBe Response.Status.UNAUTHORIZED.statusCode
      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().findClientData(any()) }
    }
  }

  /** The registering caller as the PEP presents it: client data in the `zeta-client-data` header (returned); the client is not confirmed yet. */
  private fun authenticate(
      session: KeycloakSession,
      user: UserModel,
      clientData: ZetaGuardClientData,
  ): String {
    mockkConstructor(ZetaGuardDataService::class)
    val realm = mockk<RealmModel>()
    every { session.context.realm } returns realm
    every { anyConstructed<ZetaGuardDataService>().findClientData(clientData.id) } returns clientData
    every { session.users().getUserByUsername(realm, clientData.userData!!.id) } returns user
    return Base64.getUrlEncoder().encodeToString("""{"client_id":"${clientData.id}","product_id":"demo_client","product_version":"0.1.0","platform":"apple"}""".toByteArray())
  }

  /** The caller as the PEP presents it: its client data in the `zeta-client-data` header (returned), no bearer token. */
  private fun pepCaller(session: KeycloakSession, clientId: String, clientData: ZetaGuardClientData, user: UserModel): String {
    mockkConstructor(ZetaGuardDataService::class)
    val realm = mockk<RealmModel>()
    val content = Base64.getUrlEncoder().encodeToString("""{"client_id":"$clientId","product_id":"demo_client","product_version":"0.1.0","platform":"apple"}""".toByteArray())

    every { session.context.realm } returns realm
    every { anyConstructed<ZetaGuardDataService>().findClientData(clientId) } returns clientData
    every { session.users().getUserByUsername(realm, clientData.userData!!.id) } returns user
    return content
  }

  private fun boundClientData(): ZetaGuardClientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)

  private fun mobileClientData(
      status: ClientRegistrationStatus = ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
  ): ZetaGuardClientData {
    val now = currentTime()
    return ZetaGuardClientData(CLIENT_ID, now, now).apply {
      clientAuthMethod = ClientAuthMethod.SEK_IDP
      attestationState = ClientAttestationState.VALID
      registrationStatus = status
      userData = ZetaGuardUserData("spicy-hash-of-kvnr", now, now)
    }
  }

  @Suppress("UNCHECKED_CAST")
  private fun Response.entityAsMap(): Map<String, Any?> = entity as Map<String, Any?>
}
