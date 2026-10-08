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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.commons.clientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.string.shouldContain

class ClientStatementSoftwarePostureIT : ZetaGuardFunSpecIT() {
  init {
    test("Invalid combination of posture type and platform") {
      val nonce = createNonce()
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys).toMutableMap()
      val invalidStatement =
          clientStatementData(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys, productId = AppleProductId("macos", listOf("bundle")))
      otherClaims[CLAIM_CLIENT_STATEMENT] = invalidStatement

      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldContain "Invalid combination" }
    }

    test("Invalid attestation challenge") { invalidAttestationChallenge(PostureType.SOFTWARE) }

    test("Invalid attestation timestamp") {
      val nonce = createNonce()
      val otherClaims = createOtherClaims(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys).toMutableMap()
      val invalidStatement = clientStatementData(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys, timeStampSeconds = 12)
      otherClaims[CLAIM_CLIENT_STATEMENT] = invalidStatement

      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldContain "Invalid attestation timestamp" }
    }
  }
}
