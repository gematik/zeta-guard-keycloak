/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.PKIUtil.generateECKeys
import de.gematik.zeta.zetaguard.keycloak.commons.expirationDate
import de.gematik.zeta.zetaguard.keycloak.commons.issuedAt
import de.gematik.zeta.zetaguard.keycloak.commons.now
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toRefreshToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.time.Duration
import org.apache.commons.io.ThreadUtils.sleep
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.RefreshToken

@Order(1)
class RefreshTokenIT : FunSpec() {
  val keycloakWebClient = KeycloakWebClient()
  val baseUri = keycloakWebClient.uriBuilder().build().toString()
  val realmUrl = keycloakWebClient.uriBuilder().realmUrl().toString()
  val keys = generateECKeys()

  lateinit var accessTokenResponse1: AccessTokenResponse
  lateinit var accessToken1: AccessToken
  lateinit var refreshToken1: RefreshToken

  init {
    beforeTest {
      val nonce1 = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jwt1 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
      val smcbToken1 =
          smcbTokenGenerator.generateSMCBToken(nonceString = nonce1, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))

      accessTokenResponse1 = keycloakWebClient.testExchangeToken(smcbToken1, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt1)

      accessTokenResponse1.token.shouldNotBeNull()
      accessTokenResponse1.refreshToken.shouldNotBeNull()
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

    test("Get new access token via OIDC refresh token") {
      val nonce2 = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val smcbToken2 =
          smcbTokenGenerator.generateSMCBToken(nonceString = nonce2, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
      val jwt2 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
      val dPoPToken2 = smcbTokenGenerator.generateDPoPToken(keys, endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken2)
      val accessTokenResponse2 = keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt2, dPoPToken2).shouldBeRight().reponseObject

      accessTokenResponse2.refreshToken.shouldNotBeNull()

      // TODO: Fixme with new KC version
      //      accessTokenResponse2.refreshToken.toRefreshToken().expirationDate() shouldBeAfter refreshToken1.expirationDate()
    }

    // https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25662
    test("Refresh token rotation") {
      val nonce2 = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val smcbToken2 =
          smcbTokenGenerator.generateSMCBToken(nonceString = nonce2, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
      val jwt2 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
      val dPoPToken2 = smcbTokenGenerator.generateDPoPToken(keys, endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken2)
      keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt2, dPoPToken2).shouldBeRight().reponseObject

      val nonce3 = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val smcbToken3 =
          smcbTokenGenerator.generateSMCBToken(nonceString = nonce3, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))
      val jwt3 = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl))
      val dPoPToken3 = smcbTokenGenerator.generateDPoPToken(keys, endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smcbToken3)

      keycloakWebClient.refreshToken(accessTokenResponse1.refreshToken, jwt3, dPoPToken3).shouldBeLeft().errorDescription shouldBe
          "Maximum allowed refresh token reuse exceeded"
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
