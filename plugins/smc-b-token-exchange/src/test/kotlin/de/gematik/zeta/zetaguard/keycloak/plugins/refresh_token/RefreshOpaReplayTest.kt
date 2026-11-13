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
package de.gematik.zeta.zetaguard.keycloak.plugins.refresh_token

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REQUESTED_SCOPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import java.time.Duration
import org.keycloak.OAuth2Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserSessionModel
import org.keycloak.representations.AccessToken
import org.keycloak.representations.RefreshToken

class RefreshOpaReplayTest : FunSpec() {
  init {
    val session = mockk<KeycloakSession>(relaxed = true)
    every { session.getAttribute(ATTRIBUTE_REQUESTED_SCOPES, String::class.java) } returns ""

    test("refreshOpaReplay skips sessions without an OPA snapshot") {
      val userSession = mockk<UserSessionModel>()
      every { userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) } returns null
      every { userSession.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT) } returns null

      refreshOpaReplay(userSession) shouldBe null
      refreshOpaReplay(null) shouldBe null
    }

    test("refreshOpaReplay prefers the SMC-B snapshot") {
      val userSession = mockk<UserSessionModel>()
      every { userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) } returns smcbData().toJSON()
      every { userSession.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT) } returns mobileContext().toJSON()

      val replay = refreshOpaReplay(userSession).shouldBeInstanceOf<RefreshOpaReplay.Smcb>()
      replay.data.telematikID shouldBe "1-SMC-B-test"
      replay.data.scopes shouldBe listOf("openid")
    }

    test("refreshOpaReplay reads the mobile snapshot when SMC-B is absent") {
      val userSession = mockk<UserSessionModel>()
      every { userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) } returns null
      every { userSession.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT) } returns mobileContext().toJSON()

      val replay = refreshOpaReplay(userSession).shouldBeInstanceOf<RefreshOpaReplay.Mobile>()
      replay.data.scopes shouldBe listOf("openid", "email")
      replay.data.audiences shouldBe listOf("https://fachdienst.example")
      replay.data.userIdentifier shouldBe "X110123456"
      replay.data.userCommonName shouldBe "X110123456"
    }

    context("lacksMobileGateDecision") {
      val sekIdpSession = mockk<UserSessionModel>().also { every { it.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns "X110123456" }
      val otherSession = mockk<UserSessionModel>().also { every { it.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns null }
      val mobileReplay = RefreshOpaReplay.Mobile(mobileContext())

      test("the snapshot of the refreshing client is a decision") {
        lacksMobileGateDecision(sekIdpSession, mobileReplay, "client-internal-id") shouldBe false
      }

      // Shared SSO session: another client must not refresh with the gate decision of the first one
      test("the snapshot of another client is none") {
        lacksMobileGateDecision(sekIdpSession, mobileReplay, "other-client-internal-id") shouldBe true
      }

      // An Allow without TTLs, device code or token-exchange sessions leave no snapshot
      test("a SekIDP session without snapshot has none") {
        lacksMobileGateDecision(sekIdpSession, null, "client-internal-id") shouldBe true
      }

      test("sessions without KVNR and SMC-B sessions are not affected") {
        lacksMobileGateDecision(otherSession, null, "client-internal-id") shouldBe false
        lacksMobileGateDecision(sekIdpSession, RefreshOpaReplay.Smcb(smcbData()), "smcb-client") shouldBe false
      }
    }

    test("mobile refresh replays stored scopes and audiences into the OPA input") {
      val refreshToken = RefreshToken(AccessToken()).apply { scope = "should-not-win" }
      val input = buildRefreshOpaInput(session, refreshToken, RefreshOpaReplay.Mobile(mobileContext()), "10.0.0.1", "10.0.0.2")

      input.grantType shouldBe OAuth2Constants.REFRESH_TOKEN
      input.scopes shouldBe listOf("openid", "email")
      input.audiences shouldBe listOf("https://fachdienst.example")
      input.clientId shouldBe "client-internal-id"
      input.clientPlatform shouldBe "apple"
      input.postureType shouldBe "apple"
      input.authenticationMethodsReferences shouldBe listOf("mfa")
      input.authenticationContextClassReference shouldBe "abc"
      input.userIdentifier shouldBe "X110123456"
      input.userProfessionOid shouldBe "1.2.276.0.76.4.49"
      input.userCommonName shouldBe "X110123456"
      input.userOrganizationName shouldBe "AOK"
      input.userBirthdate shouldBe "1970-01-31"
      input.ipAddress shouldBe "10.0.0.1"
      input.previousIpAddress shouldBe "10.0.0.2"
      input.attestationTimestamp shouldBe 1_753_272_000L
    }

    test("SMC-B refresh replays the certificate's common and organization name into the OPA input") {
      val refreshToken = RefreshToken(AccessToken()).apply { scope = "openid" }
      val input = buildRefreshOpaInput(session, refreshToken, RefreshOpaReplay.Smcb(smcbData()), "10.0.0.1", null)

      input.userIdentifier shouldBe "1-SMC-B-test"
      input.userCommonName shouldBe "cn"
      input.userOrganizationName shouldBe "org"
      input.userBirthdate shouldBe null
    }

    test("SMC-B refresh replays the stored attestation timestamp into the OPA input") {
      val refreshToken = RefreshToken(AccessToken()).apply { scope = "openid" }
      val input = buildRefreshOpaInput(session, refreshToken, RefreshOpaReplay.Smcb(smcbData()), "10.0.0.1", null)

      input.clientRegistrationTimestamp shouldBe 1L
      input.attestationTimestamp shouldBe 1_753_272_001L
    }

    test("mobile refresh falls back to the refresh-token scope when the snapshot has none") {
      val refreshToken = RefreshToken(AccessToken()).apply { scope = "openid profile" }
      val legacy = OpaSessionContext(
          accessTokenTTL = Duration.ofSeconds(111),
          refreshTokenTTL = Duration.ofSeconds(600),
          authenticationContextClassReference = "abc"
      )
      val input = buildRefreshOpaInput(session, refreshToken, RefreshOpaReplay.Mobile(legacy), "10.0.0.1", null)

      input.scopes shouldBe listOf("openid", "profile")
      input.previousIpAddress shouldBe "Unknown"
      input.attestationTimestamp shouldBe null
    }

    test("scopes from request win by default") {
      every { session.getAttribute(ATTRIBUTE_REQUESTED_SCOPES, String::class.java) } returns "openid email"

      val refreshToken = RefreshToken(AccessToken()).apply { scope = "openid profile" }
      val legacy = OpaSessionContext(
          accessTokenTTL = Duration.ofSeconds(111),
          refreshTokenTTL = Duration.ofSeconds(600),
          authenticationContextClassReference = "abc"
      )
      val input = buildRefreshOpaInput(session, refreshToken, RefreshOpaReplay.Mobile(legacy), "10.0.0.1", null)

      input.scopes shouldBe listOf("openid", "email")
      input.previousIpAddress shouldBe "Unknown"
      input.attestationTimestamp shouldBe null
    }
  }

  private fun mobileContext() =
      OpaSessionContext(
          accessTokenTTL = Duration.ofSeconds(111),
          refreshTokenTTL = Duration.ofSeconds(600),
          scopes = listOf("openid", "email"),
          audiences = listOf("https://fachdienst.example"),
          clientId = "client-internal-id",
          clientPlatform = "apple",
          clientRegistrationTimestamp = 1_700_000_000,
          postureType = "apple",
          clientProductID = "demo_client",
          clientProductVersion = "0.1.0",
          authenticationMethodsReferences = listOf("mfa"),
          authenticationContextClassReference = "abc",
          userIdentifier = "X110123456",
          userProfessionOid = "1.2.276.0.76.4.49",
          userCommonName = "X110123456",
          userOrganizationName = "AOK",
          userBirthdate = "1970-01-31",
          attestationTimestamp = 1_753_272_000,
      )

  private fun smcbData() =
      ZetaGuardTokenExchangeData(
          authenticationMethodsReferences = listOf("mfa"),
          authenticationContextClassReference = "abc",
          clientId = "smcb-client",
          clientPlatform = "linux",
          clientRegistrationTimestamp = 1L,
          postureType = "software",
          previousIpAddress = "10.0.0.9",
          telematikID = "1-SMC-B-test",
          professionOID = "1.2.276.0.76.4.49",
          subjectOrganisation = "org",
          subjectCommonName = "cn",
          clientIP = "10.0.0.8",
          accessTokenTTL = Duration.ofSeconds(60),
          refreshTokenTTL = Duration.ofSeconds(300),
          audiences = listOf("https://smcb.example"),
          scopes = listOf("openid"),
          attestationTimestamp = 1_753_272_001,
      )
}
