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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.smcbTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.TELEMATIK_ID
import de.gematik.zeta.zetaguard.keycloak.commons.expirationDate
import de.gematik.zeta.zetaguard.keycloak.commons.issuedAt
import de.gematik.zeta.zetaguard.keycloak.commons.now
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_IP_ADDRESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toRefreshToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.time.Duration
import org.apache.commons.io.ThreadUtils.sleep
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.RefreshToken

@Order(1)
class RefreshTokenIT : ZetaGuardFunSpecIT() {
  lateinit var accessTokenResponse1: AccessTokenResponse
  lateinit var accessToken1: AccessToken
  lateinit var refreshToken1: RefreshToken

  init {
    beforeTest {
      val nonce1 = createNonce()
      val jwt1 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce1)
      val smcbToken1 =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce1, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))

      accessTokenResponse1 = keycloakWebClient.testExchangeToken(smcbToken1, clientAssertion = jwt1)

      accessTokenResponse1.token.shouldNotBeNull().checkTokenHeader()
      accessTokenResponse1.refreshToken.shouldNotBeNull().checkTokenHeader()

      accessToken1 = accessTokenResponse1.token.toAccessToken()
      refreshToken1 = accessTokenResponse1.refreshToken.toRefreshToken()

      accessToken1.isExpired shouldBe false
      refreshToken1.isExpired shouldBe false

      val now = now().plusSeconds(1)
      accessToken1.expirationDate().isAfter(now) shouldBe true
      refreshToken1.expirationDate().isAfter(now) shouldBe true
      accessToken1.issuedAt().isBefore(now) shouldBe true
      sleep(Duration.ofSeconds(1))
    }

    test("Get new access token response via OIDC refresh token") {
      val nonce2 = createNonce()
      val smcbToken2 =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce2, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))
      val jwt2 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce2)
      val dPoPToken2 = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken2)
      val accessTokenResponse2 = keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt2, dPoPToken2).shouldBeRight().reponseObject

      accessTokenResponse2.refreshToken.shouldNotBeNull().checkTokenHeader()

      val refreshToken2 = accessTokenResponse2.refreshToken.toRefreshToken()
      refreshToken2.expirationDate() shouldBeAfter refreshToken1.expirationDate()
      refreshToken2.subject shouldBe TELEMATIK_ID
      refreshToken2.otherClaims[CLAIM_PROFESSION_OID] shouldBe
        refreshToken1.otherClaims[CLAIM_PROFESSION_OID] shouldBe
        accessToken1.otherClaims[CLAIM_PROFESSION_OID] shouldBe
        PROFESSION_OID
      refreshToken2.otherClaims[CLAIM_CLIENT_ID] shouldBe
        refreshToken1.otherClaims[CLAIM_CLIENT_ID] shouldBe
        accessToken1.otherClaims[CLAIM_CLIENT_ID] shouldBe
        ZETA_CLIENT
      refreshToken2.otherClaims[CLAIM_IP_ADDRESS] shouldBe
        refreshToken1.otherClaims[CLAIM_IP_ADDRESS] shouldBe
        accessToken1.otherClaims[CLAIM_IP_ADDRESS] shouldBe
        "127.0.0.1"
    }

    /**
     * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25662
     *
     * Configured in realm via: "revokeRefreshToken": true, "refreshTokenMaxReuse": 0,
     */
    test("Refresh token rotation") {
      val nonce2 = createNonce()
      val smcbToken2 =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce2, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))
      val jwt2 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce2)
      val dPoPToken2 = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken2)
      val accessTokenResponse = keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt2, dPoPToken2).shouldBeRight().reponseObject

      accessTokenResponse.refreshToken.shouldNotBeNull().checkTokenHeader()

      val nonce3 = createNonce()
      val smcbToken3 =
        smcbTokenGenerator.generateSMCBToken(nonceString = nonce3, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))
      val jwt3 = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce2)
      val dPoPToken3 = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken3)

      keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt3, dPoPToken3).shouldBeLeft().errorDescription shouldBe
        "Maximum allowed refresh token reuse exceeded"
    }
  }
}
