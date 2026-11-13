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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_B
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.platformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PLATFORM
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.commons.toJsonWebToken
import de.gematik.zeta.zetaguard.keycloak.commons.toRefreshToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.jose.jws.Algorithm
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.RefreshToken
import org.keycloak.representations.IDToken.NONCE
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER
import org.keycloak.util.TokenUtil.TOKEN_TYPE_DPOP

typealias ErrorHandler = (KeycloakError) -> Unit

private val EMPTY = Triple(AccessTokenResponse(), AccessToken(), RefreshToken(AccessToken()))

sealed interface DPoPMode {
  data object Disabled : DPoPMode
  data object WithoutNonce : DPoPMode
  data class Enabled(val nonce: String? = null) : DPoPMode
}

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

  protected fun createNonce(): String = keycloakWebClient.getNonce().shouldBeRight().responseObject

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
      requestedClientScope: String = SCOPE_CLIENT_B,
      dpop: DPoPMode = DPoPMode.Enabled(),
      audience: String? = "http://localhost:18080",
      expectedError: ErrorHandler? = null,
  ): Triple<AccessTokenResponse, AccessToken, RefreshToken> {
    val dPoPToken = when (dpop) {
      is DPoPMode.Enabled -> {
        @Suppress("kotlin:S6530")
        val nonce = dpop.nonce ?: subjectToken.toJsonWebToken().otherClaims[NONCE] as? String
        generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = subjectToken, nonce = nonce)
      }

      is DPoPMode.WithoutNonce -> generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = subjectToken)
      is DPoPMode.Disabled -> null
    }

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

    return if (expectedError != null) {
      either.isLeft() shouldBe true
      either.onLeft { expectedError(it) }

      EMPTY
    } else {
      val newAccessTokenResponse = either.shouldBeRight().responseObject
      val newAccessToken = newAccessTokenResponse.token.checkTokenHeader().toAccessToken()
      val newRefreshToken = newAccessTokenResponse.refreshToken.checkTokenHeader().toRefreshToken()

      if (dpop is DPoPMode.Enabled) {
        newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_DPOP
        newAccessToken.confirmation.keyThumbprint shouldBe DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()
      } else {
        newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER
      }

      newAccessToken.issuer shouldContain ZETA_REALM
      newAccessToken.issuedFor shouldBe clientId
      newAccessToken.subject shouldBe smcb.telematikId

      newAccessToken.otherClaims[CLAIM_PLATFORM] shouldBe platformProductId.productPlatform.value
      newAccessToken.otherClaims[CLAIM_CLIENT_ID] shouldBe clientId
      newAccessToken.otherClaims[CLAIM_PRODUCT_ID] shouldBe PRODUCT_ID

      if (requestedClientScope == SCOPE_CLIENT_B) {
        newAccessToken.audience shouldContain CLIENT_C_ID
      }

      newRefreshToken.subject shouldBe smcb.telematikId

      Triple(newAccessTokenResponse, newAccessToken, newRefreshToken)
    }
  }
}

fun String.checkTokenHeader(): String {
  val (_, header) = toIDTokenInfo()
  header.type shouldBe "JWT"
  header.algorithm shouldBe Algorithm.ES256

  return this
}
