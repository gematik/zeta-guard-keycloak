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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PROPERTY_PLATFORM_DISCRIMINATOR
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.platformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.toRefreshToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldContainOnlyOnce
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.common.util.Base64Url
import org.keycloak.jose.jws.Algorithm
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER
import org.keycloak.util.TokenUtil.TOKEN_TYPE_DPOP

typealias ErrorHandler = (KeycloakError) -> Unit

abstract class ZetaGuardFunSpecIT : ZetaGuardFunSpec() {
  protected val smcb: SMCBTokenHelper by lazy { SMCBTokenHelper() }
  protected val keycloakWebClient = KeycloakWebClient.instance()
  protected val smcbTokenAudience = listOf(keycloakWebClient.uriBuilder().tokenUrl().toString())
  protected val clientAssertionAudience = keycloakWebClient.uriBuilder().realmUrl().toString()

  init {
    // SMC-B tokens bind to the keys actually presented in the exchange: the registered client key and the DPoP key.
    smcb.smcbTokenGenerator.defaultClientKeyJkt = clientAssertionTokenGenerator.keys.jwkThumbPrint.toBase64()
    smcb.smcbTokenGenerator.defaultDpopKeyJkt = DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()

    afterSpec { keycloakWebClient.close() }
  }

  protected fun createNonce(): String = keycloakWebClient.getNonce().shouldBeRight().reponseObject

  protected fun createSMCBToken(nonce: String, subject: String = smcb.telematikId): String =
      smcb.smcbTokenGenerator.generateSMCBToken(
          nonceString = nonce,
          audiences = smcbTokenAudience,
          subject = subject,
          certificateChain = listOf(smcb.leafCertificate),
      )

  protected fun invalidAttestationChallenge(postureType: PostureType) {
    val realNonce = createNonce()
    val fakeNonce = "Nr-VgJg0IBOFKmDwmaeCvg"
    val otherClaims = createOtherClaims(ZETA_CLIENT, fakeNonce, clientAssertionTokenGenerator.keys, postureType = postureType)
    val invalidJWT =
        clientAssertionTokenGenerator.generateClientAssertion(
            audiences = listOf(clientAssertionAudience),
            nonceString = fakeNonce,
            otherClaims = otherClaims,
        )
    val smcbToken = createSMCBToken(realNonce)

    testExchangeToken(smcbToken, clientAssertion = invalidJWT) { it.errorDescription shouldContain "Attestation challenge does not match" }
  }

  fun testExchangeToken(
      subjectToken: String,
      clientId: String = ZETA_CLIENT,
      clientAssertion: String?,
      requestedClientScope: String? = CLIENT_B_SCOPE,
      useDPoP: Boolean = true,
      audience: String? = "http://localhost:18080",
      expectedError: ErrorHandler? = null,
  ): AccessTokenResponse {
    val dPoPToken = if (useDPoP) generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = subjectToken) else null

    val either =
        keycloakWebClient.tokenExchange(
            clientId = clientId,
            subjectToken = subjectToken,
            requestedClientScope = requestedClientScope,
            clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
            clientAssertion = clientAssertion,
            dPoPToken = dPoPToken,
            audience = audience,
        )

    if (expectedError != null) {
      either.isLeft() shouldBe true
      either.onLeft { expectedError(it) }

      return AccessTokenResponse()
    } else {
      val newAccessTokenResponse = either.shouldBeRight().reponseObject
      val newAccessToken = newAccessTokenResponse.token.toAccessToken()
      val newRefreshToken = newAccessTokenResponse.refreshToken.toRefreshToken()

      checkJSON(newAccessTokenResponse)

      if (useDPoP) {
        newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_DPOP
        newAccessToken.confirmation.keyThumbprint shouldBe DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()
      } else {
        newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER
      }

      newAccessToken.issuer shouldContain ZETA_REALM
      newAccessToken.issuedFor shouldBe clientId

      newAccessToken.subject shouldBe smcb.telematikId

      val clientId1 = newAccessToken.otherClaims[CLAIM_CLIENT_ID].shouldNotBeNull() as String
      val productId = newAccessToken.otherClaims[CLAIM_PRODUCT_ID].shouldNotBeNull() as String

      clientId1 shouldBe clientId
      productId shouldBe PRODUCT_ID

      if (requestedClientScope == CLIENT_B_SCOPE) {
        newAccessToken.audience shouldContain CLIENT_C_ID
      }

      newRefreshToken.subject shouldBe smcb.telematikId

      return newAccessTokenResponse
    }
  }
}

private fun checkJSON(newAccessTokenResponse: AccessTokenResponse) {
  val tokenString = newAccessTokenResponse.token
  val split = tokenString.split(".").also { it.size shouldBe 3 }
  val body = split[1]
  val json = Base64Url.decode(body).toString(Charsets.UTF_8)

  json shouldContainOnlyOnce "\"$PROPERTY_PLATFORM_DISCRIMINATOR\":\"${platformProductId.productPlatform.value}\""
}

fun String.checkTokenHeader() {
  val (_, header) = toIDTokenInfo()
  header.type shouldBe "JWT"
  header.algorithm shouldBe Algorithm.ES256
}
