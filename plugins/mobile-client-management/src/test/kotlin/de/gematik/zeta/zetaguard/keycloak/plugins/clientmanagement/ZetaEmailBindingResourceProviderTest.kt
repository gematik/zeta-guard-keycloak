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

import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpService
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.unmockkConstructor
import io.mockk.unmockkObject
import io.mockk.verify
import jakarta.ws.rs.core.Response
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserModel
import org.keycloak.models.cache.CachedUserModel
import org.keycloak.representations.AccessToken
import org.keycloak.services.managers.AppAuthManager
import org.keycloak.services.managers.AuthenticationManager

class ZetaEmailBindingResourceProviderTest : FunSpec() {
  init {
    afterEach {
      unmockkConstructor(AppAuthManager.BearerTokenAuthenticator::class)
      unmockkConstructor(ZetaGuardDataService::class)
      unmockkObject(EmailOtpService)
      unmockkObject(EmailOtpMailer)
    }

    test("bindEmail rejects missing email") {
      val response = ZetaEmailBindingResourceProvider(mockk()).bindEmail(null)
      response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "missing_email")
    }

    test("bindEmail stores email, issues OTP and moves registration to OTP_PENDING") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      authenticate(session, SCOPE_EMAIL_BINDING, user, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      mockkObject(EmailOtpMailer)
      every { EmailOtpService.issue(session, "mobile-client") } returns "654321"
      justRun { EmailOtpMailer.send(session, "alice@example.de", "654321") }

      val response = ZetaEmailBindingResourceProvider(session).bindEmail("alice@example.de")

      response.status shouldBe Response.Status.ACCEPTED.statusCode
      response.entityAsMap() shouldContainExactly mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP)
      verify {
        user.email = "alice@example.de"
        user.isEmailVerified = false
        EmailOtpService.issue(session, "mobile-client")
        EmailOtpMailer.send(session, "alice@example.de", "654321")
      }
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
    }

    test("bindEmail writes through CachedUserModel.delegateForUpdate") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val delegate = mockk<UserModel>(relaxed = true)
      val cached = mockk<CachedUserModel>(relaxed = true)
      every { cached.delegateForUpdate } returns delegate
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      authenticate(session, SCOPE_EMAIL_BINDING, cached, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      mockkObject(EmailOtpMailer)
      every { EmailOtpService.issue(session, "mobile-client") } returns "654321"
      justRun { EmailOtpMailer.send(session, "alice@example.de", "654321") }

      ZetaEmailBindingResourceProvider(session).bindEmail("alice@example.de")

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
      authenticate(session, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, user, "mobile-client", clientData)

      val response = ZetaEmailBindingResourceProvider(session).resend(CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.CONFLICT.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "no_pending_challenge")
    }

    test("resend re-issues OTP when registration is OTP_PENDING") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      every { user.email } returns "alice@example.de"
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      authenticate(session, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, user, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      mockkObject(EmailOtpMailer)
      every { EmailOtpService.issue(session, "mobile-client") } returns "111222"
      justRun { EmailOtpMailer.send(session, "alice@example.de", "111222") }

      val response = ZetaEmailBindingResourceProvider(session).resend(null)

      response.status shouldBe Response.Status.ACCEPTED.statusCode
      response.entityAsMap() shouldContainExactly
          mapOf("challenge_type" to CHALLENGE_TYPE_EMAIL_OTP, "email_hint" to "a*@e*.de")
      verify {
        EmailOtpService.issue(session, "mobile-client")
        EmailOtpMailer.send(session, "alice@example.de", "111222")
      }
    }

    test("verify marks user verified and registration CONFIRMED") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val user = mockk<UserModel>(relaxed = true)
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      authenticate(session, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, user, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      every { EmailOtpService.verify(session, "mobile-client", "123456") } returns true

      val response = ZetaEmailBindingResourceProvider(session).verify("123456", CHALLENGE_TYPE_EMAIL_OTP)

      response.status shouldBe Response.Status.OK.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "bound")
      verify { user.isEmailVerified = true }
      clientData.registrationStatus shouldBe ClientRegistrationStatus.CONFIRMED
    }

    test("verify writes through CachedUserModel.delegateForUpdate") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val delegate = mockk<UserModel>(relaxed = true)
      val cached = mockk<CachedUserModel>(relaxed = true)
      every { cached.delegateForUpdate } returns delegate
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      authenticate(session, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, cached, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      every { EmailOtpService.verify(session, "mobile-client", "123456") } returns true

      ZetaEmailBindingResourceProvider(session).verify("123456", null)

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
      authenticate(session, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, user, "mobile-client", clientData)
      mockkObject(EmailOtpService)
      every { EmailOtpService.verify(session, "mobile-client", "000000") } returns false

      val response = ZetaEmailBindingResourceProvider(session).verify("000000", null)

      response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "invalid_code")
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
    }

    test("endpoints reject tokens without the required scope") {
      val session = mockk<KeycloakSession>(relaxed = true)
      authenticate(session, "openid", mockk(relaxed = true), "mobile-client", mobileClientData())

      val response = ZetaEmailBindingResourceProvider(session).bindEmail("alice@example.de")

      response.status shouldBe Response.Status.UNAUTHORIZED.statusCode
      response.entityAsMap() shouldContainExactly mapOf("status" to "unauthorized")
    }
  }

  private fun authenticate(
      session: KeycloakSession,
      scope: String,
      user: UserModel,
      clientId: String,
      clientData: ZetaGuardClientData,
  ) {
    mockkConstructor(AppAuthManager.BearerTokenAuthenticator::class)
    mockkConstructor(ZetaGuardDataService::class)

    val token = AccessToken().apply { this.scope = scope }
    val client = mockk<ClientModel>()
    every { client.clientId } returns clientId
    val authResult = mockk<AuthenticationManager.AuthResult>()
    every { authResult.token() } returns token
    every { authResult.user() } returns user
    every { authResult.client() } returns client
    every { anyConstructed<AppAuthManager.BearerTokenAuthenticator>().authenticate() } returns authResult
    every { anyConstructed<ZetaGuardDataService>().findClientData(clientId) } returns clientData
  }

  private fun mobileClientData(
      status: ClientRegistrationStatus = ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
  ): ZetaGuardClientData {
    val now = currentTime()
    return ZetaGuardClientData("mobile-client", now, now).apply {
      clientAuthMethod = ClientAuthMethod.SEK_IDP
      registrationStatus = status
    }
  }

  @Suppress("UNCHECKED_CAST")
  private fun Response.entityAsMap(): Map<String, Any?> = entity as Map<String, Any?>
}
