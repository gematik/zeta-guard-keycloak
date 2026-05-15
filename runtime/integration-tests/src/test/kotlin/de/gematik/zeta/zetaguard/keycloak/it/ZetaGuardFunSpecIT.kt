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
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.smcbTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.createOtherClaims
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.toIDTokenInfo
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.keycloak.jose.jws.Algorithm

abstract class ZetaGuardFunSpecIT : ZetaGuardFunSpec() {
  protected val keycloakWebClient = KeycloakWebClient()
  private val baseUri = keycloakWebClient.uriBuilder().build().toString()
  protected val smcbTokenAudience = listOf("$baseUri/")
  protected val clientAssertionAudience = keycloakWebClient.uriBuilder().realmUrl().toString()

  protected fun createNonce(): String = keycloakWebClient.getNonce().shouldBeRight().reponseObject

  protected fun createSMCBToken(nonce: String): String =
    smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = smcbTokenAudience, certificateChain = listOf(leafCertificate))

  protected fun invalidAttestationChallenge(postureType: PostureType) {
    val realNonce = createNonce()
    val fakeNonce = "Nr-VgJg0IBOFKmDwmaeCvg"
    val otherClaims =
      createOtherClaims(
        ZETA_CLIENT,
        fakeNonce,
        clientAssertionTokenGenerator.keys,
        postureType = postureType,
      )
    val invalidJWT =
      clientAssertionTokenGenerator.generateClientAssertion(
        audiences = listOf(clientAssertionAudience),
        nonceString = fakeNonce,
        otherClaims = otherClaims,
      )
    val smcbToken = createSMCBToken(realNonce)

    keycloakWebClient.testExchangeToken(smcbToken, clientAssertion = invalidJWT) {
      it.errorDescription shouldContain "Attestation challenge does not match"
    }
  }
}

fun String.checkTokenHeader() {
    val (_, header) = toIDTokenInfo()
    header.type shouldBe "JWT"
    header.algorithm shouldBe Algorithm.ES256
}
