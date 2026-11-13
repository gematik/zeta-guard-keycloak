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

import de.gematik.zeta.zetaguard.keycloak.commons.server.USE_DPOP_NONCE
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotBeBlank
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.keycloak.OAuth2Constants.DPOP_NONCE_HEADER
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.events.Errors.INVALID_TOKEN

class TokenExchangeDPoPIT : AbstractTokenExchangeIT() {
  init {
    test("External token exchange fails without DPoP token") {
      val nonce = createNonce()
      val jws = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jws, dpop = DPoPMode.Disabled) {
        // Checked in DPoPUtil.validateDPoP
        it.error shouldBe INVALID_REQUEST
        it.errorDescription shouldBe "DPoP proof is missing"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("DPoP proof with invalid nonce is rejected") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt, dpop = DPoPMode.Enabled("this is not a valid nonce")) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain INVALID_NONCE_VALUE
      }
    }

    test("DPoP proof without nonce is rejected and sets nonce response header") {
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt, dpop = DPoPMode.WithoutNonce) {
        it.statusCode shouldBe SC_BAD_REQUEST
        it.error shouldBe USE_DPOP_NONCE
        it.errorDescription shouldContain "requires nonce"

        // https://www.rfc-editor.org/rfc/rfc9449.html#section-8
        it.responseHeaders[DPOP_NONCE_HEADER].shouldNotBeBlank()
      }
    }
  }
}
