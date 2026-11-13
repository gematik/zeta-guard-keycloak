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

import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_B
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.Duration
import org.apache.commons.lang3.Strings
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.keycloak.OAuthErrorException.INVALID_GRANT

class TokenExchangeClaimsIT : AbstractTokenExchangeIT() {
  init {
    test("External token exchange without 'exp' claim is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, withExp = false)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain "missing required 'exp'"
      }
    }

    test("External token exchange without 'iat' claim is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, withIat = false)

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain "missing required 'iat'"
      }
    }

    test("External token exchange with 'iat' in the future is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, iatOffsetSeconds = Duration.ofHours(1).toSeconds())

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain "'iat' is in the future"
      }
    }

    test("External token exchange with expired 'exp' is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBTokenRaw(nonce, expOffsetSeconds = -Duration.ofHours(1).toSeconds())

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldContain "has expired"
      }
    }

    test("External token exchange fails with invalid audience") {
      val nonce = createNonce()
      val jws = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              subject = smcb.telematikId,
              nonceString = nonce,
              audiences = listOf(ZETA_CLIENT),
              certificateChain = listOf(smcb.leafCertificate),
          )

      testExchangeToken(smcbToken, clientAssertion = jws, requestedClientScope = SCOPE_CLIENT_B) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
        it.errorDescription shouldBe "Expected audience not available in the token"
      }
    }

    test("subject_token with base URL as audience is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val baseUrl = Strings.CS.appendIfMissing(keycloakWebClient.uriBuilder().build().toString(), "/")
      val smcbToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              subject = smcb.telematikId,
              audiences = listOf(baseUrl),
              certificateChain = listOf(smcb.leafCertificate),
          )

      testExchangeToken(smcbToken, clientAssertion = jwt) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_GRANT
      }
    }
  }
}
