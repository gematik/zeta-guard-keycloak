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

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.smcbTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldContain
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE

/**
 * Since it permanently exceeds the limit of clients, this test should run after [ClientRegistrationIT] and [ExternalTokenExchangeIT].
 *
 * See docker-compose-it.yml.
 */
@Order(10)
class XXSMCBUserMaxClientsIT : ZetaGuardFunSpecIT() {
  init {
    test("Maximum number of clients per user") {
      var i = 0
      var error: KeycloakError? = null

      while (i <= 20 && error == null) { // Should fail eventually, see docker-compose-it.yml
        val oidcClientResponse1 = keycloakWebClient.createClientOIDC(clientAssertionTokenGenerator.keys.jwks).shouldBeRight().reponseObject
        val nonce = createNonce()
        val smbcToken =
            smcbTokenGenerator.generateSMCBToken(
                nonceString = nonce,
                audiences = smcbTokenAudience,
                issuer = oidcClientResponse1.clientId,
                issuedFor = oidcClientResponse1.clientId,
                certificateChain = listOf(leafCertificate),
            )
        val jws = clientAssertionTokenGenerator.generateClientAssertion(oidcClientResponse1, nonce)
        val dPoPToken = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smbcToken)

        keycloakWebClient
            .tokenExchange(
                clientId = oidcClientResponse1.clientId,
                subjectToken = smbcToken,
                subjectTokenType = JWT_TOKEN_TYPE,
                requestedClientScope = CLIENT_B_SCOPE,
                clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
                clientAssertion = jws,
                dPoPToken = dPoPToken,
                audience = "http://localhost:18080",
            )
            .onLeft { error = it }
        i++
      }

      error.shouldNotBeNull().errorDescription shouldContain "Too many clients"
    }
  }
}
