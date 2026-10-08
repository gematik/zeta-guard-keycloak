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

import arrow.core.Either
import arrow.core.raise.either
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.comparables.shouldBeGreaterThanOrEqualTo
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.representations.idm.ClientRepresentation

class ClientExpirationIT : ZetaGuardFunSpecIT() {
  init {
    setZetaClientClientLastAccess() // Prevent zeta-client to be expired

    test("Reaching maximum number of clients causes expiry") {
      val clientId = createClient().shouldBeRight()
      val clients1 = keycloakWebClient.clients().filter { it.clientId.count { c -> c == '-' } == 4 } // Match synthetic UUID client ids
      createManyClients().shouldBeNull()
      val clients2 = keycloakWebClient.clients().filter { it.clientId.count { c -> c == '-' } == 4 }

      clients2.size shouldBeGreaterThanOrEqualTo clients1.size
      clients2.size shouldBe 20
      clients2.map { it.clientId } shouldNotContain clientId
    }
  }

  private fun createManyClients(): KeycloakError? {
    (1..22).forEach { _ ->
      createClient().onLeft { ex ->
        return ex
      }
    }

    return null
  }

  private fun createClient(): Either<KeycloakError, String> = either {
    val oidcClientResponse1 = keycloakWebClient.createClientOIDC(clientAssertionTokenGenerator.keys.jwks).shouldBeRight().reponseObject
    val nonce = createNonce()
    val smbcToken =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            subject = smcb.telematikId,
            audiences = smcbTokenAudience,
            issuer = oidcClientResponse1.clientId,
            issuedFor = oidcClientResponse1.clientId,
            certificateChain = listOf(smcb.leafCertificate),
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
        .map { oidcClientResponse1.clientId }
        .bind()
  }
}

fun KeycloakWebClient.clients(): List<ClientRepresentation> =
    withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(ZETA_REALM)

      realmResource.clients().findAll()
    }
