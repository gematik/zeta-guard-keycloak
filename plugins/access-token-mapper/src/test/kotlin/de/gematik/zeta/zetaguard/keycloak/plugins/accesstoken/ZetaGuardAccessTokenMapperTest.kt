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
package de.gematik.zeta.zetaguard.keycloak.plugins.accesstoken

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.LinuxProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Platform
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_COMMON_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_IP_ADDRESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_ORGANIZATION_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PLATFORM
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import java.lang.reflect.InvocationTargetException
import java.time.Duration
import java.time.LocalDateTime
import java.time.ZoneId
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ProtocolMapperModel
import org.keycloak.models.UserSessionModel
import org.keycloak.representations.AccessToken
import org.keycloak.representations.IDToken
import org.keycloak.representations.RefreshToken
import org.keycloak.representations.dpop.DPoP

class ZetaGuardAccessTokenMapperTest : FunSpec() {
  init {
    beforeEach {
      mockkObject(OidcFlowSettings)
      every { OidcFlowSettings.isEnabled() } returns true
    }
    afterEach {
      unmockkObject(OidcFlowSettings)
      unmockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
    }

    test("setClaim applies mobile OPA access-token TTL") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      every { currentTime() } returns LocalDateTime.of(2026, 1, 1, 0, 0, 0)

      val token = AccessToken().apply { exp(1L) }
      invokeSetClaim(token, mobileOpaSession())

      token.exp shouldBe LocalDateTime.of(2026, 1, 1, 0, 1, 51).atZone(ZoneId.systemDefault()).toEpochSecond()
    }

    test("transformRefreshToken applies mobile OPA refresh-token TTL") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      every { currentTime() } returns LocalDateTime.of(2026, 1, 1, 0, 0, 0)

      val token = RefreshToken(AccessToken()).apply { exp(1L) }
      val ctx = tokenContext(mobileOpaSession())
      ZetaGuardAccessTokenMapper().transformRefreshToken(token, mockk(), ctx.session, ctx.userSession, ctx.clientSessionCtx)

      token.exp shouldBe LocalDateTime.of(2026, 1, 1, 0, 10, 0).atZone(ZoneId.systemDefault()).toEpochSecond()
    }

    test("setClaim leaves expiration unchanged when mobile OPA TTLs are absent") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      every { currentTime() } returns LocalDateTime.of(2026, 1, 1, 0, 0, 0)

      val token = AccessToken().apply { exp(42L) }
      val userSession = mockk<UserSessionModel>(relaxed = true)
      every { userSession.getNote(any()) } returns null
      every { userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns "X110123456"

      invokeSetClaim(token, userSession)

      token.exp shouldBe 42L
    }

    test("setClaim fails closed when mobile flow is disabled and SMC-B context is missing") {
      every { OidcFlowSettings.isEnabled() } returns false

      val ex = shouldThrow<IllegalStateException> { invokeSetClaim(AccessToken(), mobileOpaSession()) }
      ex.message shouldBe "SMC-B context not found"
    }

    test("setClaim fails closed when neither SMC-B nor mobile context is present") {
      val userSession = mockk<UserSessionModel>(relaxed = true)
      every { userSession.getNote(any()) } returns null

      val ex = shouldThrow<IllegalStateException> { invokeSetClaim(AccessToken(), userSession) }
      ex.message shouldBe "Mobile user KVNR not found"
    }

    test("setClaim fails closed when SMC-B context is present without a client statement") {
      val userSession = mockk<UserSessionModel>(relaxed = true)
      every { userSession.getNote(any()) } returns null
      every { userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) } returns smcbData().toJSON()

      val ex = shouldThrow<IllegalStateException> { invokeSetClaim(AccessToken(), userSession) }
      ex.message shouldBe "Client statement data not found"
    }

    test("setClaim maps SMC-B claims even when mobile flow is disabled") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      every { currentTime() } returns LocalDateTime.of(2026, 1, 1, 0, 0, 0)
      every { OidcFlowSettings.isEnabled() } returns false

      val token = AccessToken().apply { exp(1L) }
      invokeSetClaim(token, smcbSession())

      token.subject shouldBe "1-SMC-B-test"
      token.otherClaims[CLAIM_COMMON_NAME] shouldBe "cn"
      token.otherClaims[CLAIM_PROFESSION_OID] shouldBe "1.2.276.0.76.4.49"
      token.otherClaims[CLAIM_ORGANIZATION_NAME] shouldBe "org"
      token.otherClaims[CLAIM_IP_ADDRESS] shouldBe "10.0.0.8"
      token.otherClaims[CLAIM_PRODUCT_ID] shouldBe "demo_client"
      token.otherClaims[CLAIM_PRODUCT_VERSION] shouldBe "0.2.0"
      token.otherClaims[CLAIM_PLATFORM] shouldBe "linux"
      token.exp shouldBe LocalDateTime.of(2026, 1, 1, 0, 1, 0).atZone(ZoneId.systemDefault()).toEpochSecond()
    }
  }

  private fun mobileOpaSession(): UserSessionModel {
    val userSession = mockk<UserSessionModel>(relaxed = true)
    every { userSession.getNote(any()) } returns null
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns "X110123456"
    every { userSession.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT) } returns
        OpaSessionContext(accessTokenTTL = Duration.ofSeconds(111), refreshTokenTTL = Duration.ofSeconds(600), authenticationContextClassReference = "abc").toJSON()
    return userSession
  }

  private fun invokeSetClaim(token: IDToken, userSession: UserSessionModel) {
    val ctx = tokenContext(userSession)
    val method =
        ZetaGuardAccessTokenMapper::class.java.getDeclaredMethod(
            "setClaim",
            IDToken::class.java,
            ProtocolMapperModel::class.java,
            UserSessionModel::class.java,
            KeycloakSession::class.java,
            ClientSessionContext::class.java,
        )
    method.isAccessible = true
    try {
      method.invoke(ZetaGuardAccessTokenMapper(), token, mockk<ProtocolMapperModel>(), userSession, ctx.session, ctx.clientSessionCtx)
    } catch (e: InvocationTargetException) {
      throw e.targetException
    }
  }

  private fun smcbSession(): UserSessionModel {
    val userSession = mockk<UserSessionModel>(relaxed = true)
    every { userSession.getNote(any()) } returns null
    every { userSession.getNote(ATTRIBUTE_SMCB_CONTEXT) } returns smcbData().toJSON()
    every { userSession.getNote(ATTRIBUTE_CLIENT_STATEMENT_DATA) } returns clientStatement().toJSON()
    return userSession
  }

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
      )

  private fun clientStatement() =
      ClientStatementData(
          "smcb-client",
          Platform.LINUX,
          PostureType.SOFTWARE,
          SoftwarePosture(LinuxProductId("deb", "app"), "demo_client", "0.2.0", "Linux", "6.1", "x86_64", "pubkey", "challenge"),
          4711L,
      )

  private fun tokenContext(userSession: UserSessionModel): TokenCtx {
    val client = mockk<ClientModel>(relaxed = true)
    every { client.clientId } returns "mobile-client"
    val clientSessionCtx = mockk<ClientSessionContext>(relaxed = true)
    every { clientSessionCtx.clientSession.client } returns client
    val session = mockk<KeycloakSession>(relaxed = true)
    every { session.getAttribute(any(), DPoP::class.java) } returns null
    return TokenCtx(session, userSession, clientSessionCtx)
  }

  private data class TokenCtx(
      val session: KeycloakSession,
      val userSession: UserSessionModel,
      val clientSessionCtx: ClientSessionContext,
  )
}
