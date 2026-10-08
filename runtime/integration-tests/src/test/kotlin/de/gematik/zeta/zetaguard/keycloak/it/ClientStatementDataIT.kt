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

import de.gematik.zeta.zetaguard.keycloak.commons.clientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.matchers.string.shouldContain

class ClientStatementDataIT : ZetaGuardFunSpecIT() {
  init {
    test("Missing claims") {
      val nonce = createNonce()
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = mapOf(),
          )
      val smcbToken = createSMCBToken(nonce)

      testExchangeToken(smcbToken, clientAssertion = jwt) { it.errorDescription shouldContain CLAIM_CLIENT_STATEMENT }
    }

    test("Token exchange succeeds without 'client-self-assessment' claim") {
      val nonce = createNonce()
      val smcbToken = createSMCBToken(nonce)
      val otherClaims = mapOf(CLAIM_CLIENT_STATEMENT to clientStatementData(ZETA_CLIENT, nonce, clientAssertionTokenGenerator.keys))
      val jwt =
          clientAssertionTokenGenerator.generateClientAssertion(
              audiences = listOf(clientAssertionAudience),
              nonceString = nonce,
              otherClaims = otherClaims,
          )

      testExchangeToken(smcbToken, clientAssertion = jwt)
    }
  }
}
