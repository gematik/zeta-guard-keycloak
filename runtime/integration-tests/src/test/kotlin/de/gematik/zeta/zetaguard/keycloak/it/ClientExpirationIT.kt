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
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_B
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.comparables.shouldBeGreaterThanOrEqualTo
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.representations.idm.ClientRepresentation

private const val MAX_CLIENTS = 20 // SMCB_USER_MAX_CLIENTS in docker-compose-it.yml
private const val CONCURRENT_CLIENTS = 10

class ClientExpirationIT : ZetaGuardFunSpecIT() {
  init {
    setZetaClientClientLastAccess() // Prevent zeta-client from being expired

    test("Reaching maximum number of clients causes expiry") {
      val clientId = createClient().shouldBeRight()
      val clients1 = keycloakWebClient.clients().filter { it.clientId.count { c -> c == '-' } == 4 } // Match synthetic UUID client ids
      createManyClients().shouldBeNull()
      val clients2 = keycloakWebClient.clients().filter { it.clientId.count { c -> c == '-' } == 4 }

      clients2.size shouldBeGreaterThanOrEqualTo clients1.size
      clients2.size shouldBe 20
      clients2.map { it.clientId } shouldNotContain clientId
    }

    test("ANFTI2-1031: Concurrent token exchanges of new clients keep the maximum number of clients") {
      createManyClients().shouldBeNull() // Make sure the limit is reached, so every new client has to evict one

      // Prepared one after another, so only the token exchanges themselves run concurrently
      val exchanges = (1..CONCURRENT_CLIENTS).map { prepareTokenExchange() }
      val results = coroutineScope {
        exchanges
            .map { exchange ->
              // KeycloakWebClient keeps the last response body, so each request uses its own instance
              async(Dispatchers.IO) { KeycloakWebClient.instance().use { exchange.execute(it) } }
            }
            .awaitAll()
      }

      results.forEach { it.shouldBeRight() }

      val userClientIds = lookupUserClientIds(smcb.telematikId.toSpicyHash().lowercase())

      userClientIds shouldHaveSize MAX_CLIENTS
      userClientIds shouldContainAll exchanges.map { it.clientId }
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

  private fun createClient(): Either<KeycloakError, String> = prepareTokenExchange().execute(keycloakWebClient)

  /** Registers a new client and creates the tokens for its first token exchange, which binds it to the SMC-B user. */
  private fun prepareTokenExchange(): PreparedTokenExchange {
    val request = ClientRegistrationRequestFactory.createClientRegistrationRequest(clientAssertionTokenGenerator.keys, null)
    val oidcClientResponse1 = keycloakWebClient.registerClientOIDC(clientRegistrationRequest = request).shouldBeRight().responseObject
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
    val dPoPToken = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smbcToken, nonce = nonce)

    return PreparedTokenExchange(oidcClientResponse1.clientId, smbcToken, jws, dPoPToken)
  }
}

private class PreparedTokenExchange(val clientId: String, val subjectToken: String, val clientAssertion: String, val dPoPToken: String) {
  fun execute(webClient: KeycloakWebClient): Either<KeycloakError, String> = either {
    webClient
        .tokenExchange(
            clientId = clientId,
            subjectToken = subjectToken,
            subjectTokenType = JWT_TOKEN_TYPE,
            requestedClientScope = SCOPE_CLIENT_B,
            clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
            clientAssertion = clientAssertion,
            dPoPToken = dPoPToken,
            audience = "http://localhost:18080",
        )
        .map { clientId }
        .bind()
  }
}

/** Ids of the clients bound to the user, as stored in `ZETA_CLIENT_DATA`. */
private fun lookupUserClientIds(userName: String): List<String> =
    JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
      it.createEntityManager()
          .createQuery("SELECT c.id FROM ZetaGuardClientData c WHERE c.userData.id = :userName", String::class.java)
          .setParameter("userName", userName)
          .resultList
    }

fun KeycloakWebClient.clients(): List<ClientRepresentation> =
    withKeycloak(clientId = ADMIN_CLIENT) {
      val realmResource = realm(ZETA_REALM)

      realmResource.clients().findAll()
    }
