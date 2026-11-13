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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.nio.charset.StandardCharsets
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_FORBIDDEN
import org.keycloak.OAuthErrorException.INVALID_GRANT
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.common.util.Base64Url
import org.keycloak.events.Errors.INVALID_TOKEN

class TokenExchangeJWTValidationIT : AbstractTokenExchangeIT() {
  init {
    context("A_27802-03 — RFC 7515 §5.2 step 5: crit (critical) header parameter") {
      test("SMC-B subject token with an unsupported crit extension is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
        val smcbToken = createSMCBTokenWithExtraHeaders(nonce, extraHeaders = mapOf("crit" to listOf(X_CUSTOM_EXT), X_CUSTOM_EXT to "value"))

        testExchangeToken(smcbToken, clientAssertion = jwt) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
          it.errorDescription shouldContain "crit"
        }
      }

      test("client assertion with an unsupported crit extension is rejected") {
        val nonce = createNonce()
        val smcbToken = createSMCBToken(nonce)
        val jwt = createClientAssertionWithExtraHeaders(nonce, extraHeaders = mapOf("crit" to listOf(X_CUSTOM_EXT), X_CUSTOM_EXT to "value"))

        testExchangeToken(smcbToken, clientAssertion = jwt) {
          it.statusCode shouldBe SC_BAD_REQUEST
          it.error shouldBe INVALID_REQUEST
          it.errorDescription shouldContain "crit"
        }
      }
    }

    context("A_27802-03 — RFC 7519 §7.2 step 8: cty (content type) header, nested JWT indicator") {
      test("SMC-B subject token with any cty header is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
        val smcbToken = createSMCBTokenWithExtraHeaders(nonce, extraHeaders = mapOf("cty" to "JWT"))

        testExchangeToken(smcbToken, clientAssertion = jwt) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
          it.errorDescription shouldContain "cty"
        }
      }

      test("client assertion with any cty header is rejected") {
        val nonce = createNonce()
        val smcbToken = createSMCBToken(nonce)
        val jwt = createClientAssertionWithExtraHeaders(nonce, extraHeaders = mapOf("cty" to "JWT"))

        testExchangeToken(smcbToken, clientAssertion = jwt) {
          it.statusCode shouldBe SC_BAD_REQUEST
          it.error shouldBe INVALID_REQUEST
          it.errorDescription shouldContain "cty"
        }
      }
    }

    context("A_27802-03 — RFC 7515 §5.2 step 8 / RFC 7519 §7.2: algorithm validation") {
      test("SMC-B subject token signed with an algorithm other than ES256 is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
        val smcbToken = createSMCBTokenWithExtraHeaders(nonce, algOverride = "none")

        testExchangeToken(smcbToken, clientAssertion = jwt) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
        }
      }
    }

    context("A_27802-03 — RFC 7515 §5.2 step 1–3 / RFC 7519 §7.2 step 1–4: JWS structure validation") {
      test("a subject token that is not a valid JWS (no dots) is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)

        testExchangeToken("not-a-jws-at-all", clientAssertion = jwt, dpop = DPoPMode.Enabled(nonce)) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
          it.errorDescription shouldContain "subject token"
        }
      }

      test("a subject token with an invalid base64url header is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)

        testExchangeToken("!!!invalid-base64!!!.payload.signature", clientAssertion = jwt, dpop = DPoPMode.Enabled(nonce)) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
          it.errorDescription shouldContain "subject token"
        }
      }

      test("a subject token whose header is not valid JSON is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
        val notJson = Base64Url.encode("this is not json".toByteArray(StandardCharsets.UTF_8))
        val payload = Base64Url.encode("{}".toByteArray(StandardCharsets.UTF_8))

        testExchangeToken("$notJson.$payload.fakesig", clientAssertion = jwt, dpop = DPoPMode.Enabled(nonce)) {
          it.statusCode shouldBe SC_FORBIDDEN
          it.error shouldBe INVALID_TOKEN
          it.errorDescription shouldContain "subject token"
        }
      }
    }

    context("A_27802-03 — RFC 7515 §5.2 step 7–8: signature validation") {
      test("a subject token with a tampered signature is rejected") {
        val nonce = createNonce()
        val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
        val validToken = createSMCBToken(nonce)
        val parts = validToken.split(".")
        val tamperedSig = Base64Url.encode(ByteArray(64) { 0x42 })

        testExchangeToken("${parts[0]}.${parts[1]}.$tamperedSig", clientAssertion = jwt, dpop = DPoPMode.Enabled(nonce)) {
          it.statusCode shouldBe SC_BAD_REQUEST
          it.error shouldBe INVALID_GRANT
        }
      }
    }
  }
}
