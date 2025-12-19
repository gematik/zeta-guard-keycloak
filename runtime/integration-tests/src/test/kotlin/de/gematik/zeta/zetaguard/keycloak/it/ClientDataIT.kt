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
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.asMap
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.FIELD_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.createClientData
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_SELF_ASSESSMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.string.shouldContain

@Order(1)
class ClientDataIT : FunSpec() {
  val keycloakWebClient = KeycloakWebClient()
  val baseUri = keycloakWebClient.uriBuilder().build().toString()
  val realmUrl = keycloakWebClient.uriBuilder().realmUrl().toString()

  init {
    test("Valid client data") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val otherClaims = mapOf(CLAIM_CLIENT_SELF_ASSESSMENT to createClientData(ZETA_CLIENT).asMap())
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt)
    }

    test("Enforce parse error") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val map = createClientData(ZETA_CLIENT).asMap().toMutableMap().apply { remove(FIELD_CLIENT_ID) }
      val otherClaims = mapOf(CLAIM_CLIENT_SELF_ASSESSMENT to map)
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain "clientId"
      }
    }

    test("Missing client data") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), mapOf())
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain CLAIM_CLIENT_SELF_ASSESSMENT
      }
    }

    test("Invalid client data") {
      val nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      val otherClaims = mapOf(CLAIM_CLIENT_SELF_ASSESSMENT to createClientData(ZETA_CLIENT, "jens"))
      val jwt = jwsTokenGenerator.generateClientAssertion(ZETA_CLIENT, listOf(realmUrl), otherClaims)
      val smcbToken = createSMCBToken(nonce)

      keycloakWebClient.testExchangeToken(smcbToken, requestedClientScope = CLIENT_B_SCOPE, clientAssertion = jwt) {
        it.errorDescription shouldContain "Invalid Email address"
      }
    }
  }

  private fun createSMCBToken(nonce: String): String =
      smcbTokenGenerator.generateSMCBToken(nonceString = nonce, audiences = listOf(baseUri), certificateChain = listOf(leafCertificate))

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
