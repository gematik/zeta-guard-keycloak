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

import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.RevocationStream.Companion.FIELD_UNTIL
import de.gematik.zeta.zetaguard.keycloak.it.RevocationStream.Companion.FIELD_WHAT
import de.gematik.zeta.zetaguard.keycloak.it.RevocationStream.Companion.FIELD_WHEN
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.longs.shouldBeBetween
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_NOT_FOUND
import org.keycloak.representations.AccessToken

/**
 * The revocation API under .../realms/zeta-guard/zeta-guard-revocation, from the point of view of a PEP: report a token over POST, learn about blocks
 * over the GET stream.
 */
class RevocationIT : ZetaGuardFunSpecIT() {

  init {
    test("Reporting an access token blocks its session and ends it") {
      RevocationStream(keycloakWebClient).use { stream ->
        val (token, accessToken) = createSession()
        val sessionId = accessToken.sessionId.shouldNotBeNull()

        keycloakWebClient.reportRevocation(token).shouldBeRight()

        val block = stream.awaitBlock(sessionId)

        // The field names are the contract with the PEP; a rename here breaks it silently.
        block.keys shouldContainExactlyInAnyOrder listOf(FIELD_WHEN, FIELD_UNTIL, FIELD_WHAT)
        // The block outlives the reported token exactly, so it may be forgotten as soon as the token could no longer be presented.
        (block[FIELD_UNTIL] as Number).toLong() shouldBe accessToken.exp
        (block[FIELD_WHEN] as Number).toLong() shouldBeLessThanOrEqual accessToken.exp

        // The session is gone, so the admin API no longer finds it.
        keycloakWebClient.adminRevokeSession(sessionId).shouldBeLeft().statusCode shouldBe SC_NOT_FOUND
      }
    }

    test("A subscriber that connects late receives the block in its snapshot") {
      val (token, accessToken) = createSession()
      val sessionId = accessToken.sessionId.shouldNotBeNull()

      keycloakWebClient.reportRevocation(token).shouldBeRight()

      // Nothing is reported while this subscriber is connected: what it sees can only come from the snapshot, which is what makes a reconnect
      // sufficient for the PEP to catch up.
      RevocationStream(keycloakWebClient).use { stream -> stream.awaitBlock(sessionId)[FIELD_WHAT] shouldBe sessionId }
    }

    test("Ending a session as admin blocks it, without anyone reporting a token") {
      RevocationStream(keycloakWebClient).use { stream ->
        val (_, accessToken) = createSession()
        val sessionId = accessToken.sessionId.shouldNotBeNull()

        keycloakWebClient.adminRevokeSession(sessionId).shouldBeRight()

        // No token is available at event time, and the token's OPA-granted TTL dies with the session, so the block gets a flat hour. It therefore
        // outlives this token's exp on purpose: over-blocking costs a cache entry, under-blocking would leave the revoked session usable.
        val until = (stream.awaitBlock(sessionId)[FIELD_UNTIL] as Number).toLong()
        until shouldBeGreaterThan accessToken.exp
        until.shouldBeBetween(accessToken.exp + 3000, accessToken.exp + 4200)
      }
    }

    test("A body that is not a token of this realm is rejected") {
      keycloakWebClient.reportRevocation("not-a-token").shouldBeLeft().statusCode shouldBe SC_BAD_REQUEST
      keycloakWebClient.reportRevocation("").shouldBeLeft().statusCode shouldBe SC_BAD_REQUEST
    }
  }

  /** A fresh session with a DPoP-bound access token, as a client would obtain it. */
  private fun createSession(): Pair<String, AccessToken> {
    val nonce = createNonce()
    val clientAssertion = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
    val accessTokenResponse = testExchangeToken(createSMCBToken(nonce), clientAssertion = clientAssertion)

    return accessTokenResponse.token to accessTokenResponse.token.toAccessToken()
  }
}
