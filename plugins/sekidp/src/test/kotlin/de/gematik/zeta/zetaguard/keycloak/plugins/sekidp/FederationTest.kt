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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.plugins.sekidp.FederationEndpoint.FEDMASTER_FETCH
import de.gematik.zeta.zetaguard.keycloak.plugins.sekidp.FederationEndpoint.FEDMASTER_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.plugins.sekidp.FederationEndpoint.IDP_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.plugins.sekidp.FederationEndpoint.SIGNED_JWKS
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.keycloak.common.util.Time
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.KeycloakSession

/**
 * Component tests for [Federation] and [VouchedSekIDP] against a localhost [FederationMock].
 *
 * Brokering itself belongs to [SekIDPIdentityProviderTest]. The production caches are static; each mock issues under
 * its own prefix so no two tests share a cache key.
 */
class FederationTest : ZetaGuardFunSpec() {

  /** The client behind the mocked session, one per test. */
  private lateinit var httpClient: CloseableHttpClient

  init {
    beforeEach { httpClient = HttpClients.createDefault() }

    afterEach { httpClient.close() }

    context("verifyIdToken — trust chain and signature (A_29672)") {
      test("accepts an ID token signed with the protocol key from the signed JWK set") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          val idToken = federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().verifyIdToken(mock.idToken()).shouldBeRight()

          idToken.path("sub").asText() shouldBe "mock-subject"
        }
      }

      test("rejects an ID token signed with a key the SekIDP never published") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          val foreignKey = FederationKey(mock.protocolKey.kid)

          rejectionReason(mock, federation, mock.idToken(key = foreignKey)) shouldContain "has an invalid signature"
        }
      }

      test("rejects an ID token whose kid is not in the signed JWK set") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          rejectionReason(mock, federation, mock.idToken(kid = "unknown-kid")) shouldContain "unknown kid »unknown-kid«"
        }
      }

      test("rejects an ID token that is not signed with ES256 (A_23034-02)") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          rejectionReason(mock, federation, mock.idToken(alg = "ES384")) shouldContain "only ES256 is supported"
        }
      }

      test("rejects an ID token without a kid in its JWS header") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          rejectionReason(mock, federation, mock.idToken(kid = null)) shouldContain "has no »kid«"
        }
      }

      test("rejects an ID token signed with the federation key instead of the protocol key") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          // Only the signed JWK set names ID-token signers.
          rejectionReason(mock, federation, mock.idToken(key = mock.federationKey)) shouldContain "unknown kid »${mock.federationKey.kid}«"
        }
      }

      test("rejects the token when the Federation Master vouches for the SekIDP with no keys") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(
              FEDMASTER_FETCH, mock.fedmasterKey.sign(mock.defaultVouchBody() + ("jwks" to mapOf("keys" to emptyList<Any>())))
          )

          rejectionReason(mock, federation, mock.idToken()) shouldContain "carries no keys"
        }
      }

      test("rejects the token when the vouch request fails") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(FEDMASTER_FETCH, """{"error":"not_found"}""", status = 404)

          rejectionReason(mock, federation, mock.idToken()) shouldContain "is not a JWS"
        }
      }

      test("rejects the token when the vouching statement is not signed by the Federation Master") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          val impostor = FederationKey(mock.fedmasterKey.kid)
          mock.serve(FEDMASTER_FETCH, impostor.sign(mock.defaultVouchBody()))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "Federation Master's statement about"
        }
      }

      test("rejects the token when the signed JWK set is issued for someone else") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody() + ("iss" to "https://someone.else")))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "is issued by »https://someone.else«"
        }
      }

      test("rejects the token when the signed JWK set is not signed by the vouched federation key") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(SIGNED_JWKS, mock.protocolKey.sign(mock.defaultSignedJwksBody()))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "signed JWK set"
        }
      }

      test("rejects the token when the Federation Master statement is not a JWS") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(FEDMASTER_STATEMENT, "this-is-not-a-jws")

          rejectionReason(mock, federation, mock.idToken()) shouldContain "Federation Master entity statement"
        }
      }

      test("rejects the token when the SekIDP entity statement names no signed_jwks_uri") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(IDP_STATEMENT, mock.federationKey.sign(mock.idpStatementBodyWithout("signed_jwks_uri")))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "no metadata.openid_provider.signed_jwks_uri"
        }
      }

      test("rejects the token when the Federation Master entity statement has expired") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(FEDMASTER_STATEMENT, mock.fedmasterKey.sign(mock.defaultFedmasterStatementBody() + ("exp" to Time.currentTime() - 10)))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "expired"
        }
      }

      test("rejects the token when the signed JWK set has expired, although its signature still verifies") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody() + ("exp" to Time.currentTime() - 10)))

          rejectionReason(mock, federation, mock.idToken()) shouldContain "expired"
        }
      }

      test("leaves the ID token's own exp to Keycloak's validateToken, which honors allowedClockSkew") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          val expired = mock.idToken(claims = mapOf("exp" to Time.currentTime() - 60))

          federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().verifyIdToken(expired).shouldBeRight().path("sub").asText() shouldBe "mock-subject"
        }
      }

      test("rejects an ID token issued by someone other than the vouched IDP") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          rejectionReason(mock, federation, mock.idToken(claims = mapOf("iss" to "https://someone.else"))) shouldContain
              "is issued by »https://someone.else«"
        }
      }
    }

    context("RFC 7515 §5.2 / RFC 7519 §7.2 — JWS/JWT validation steps (A_27802-03)") {
      test("rejects an ID token with a crit header naming an unsupported extension (RFC 7515 §5.2 step 5)") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          val jws = mock.idToken(extraHeaders = mapOf("crit" to listOf("x-custom-ext"), "x-custom-ext" to "value"))

          rejectionReason(mock, federation, jws) shouldContain "crit"
        }
      }

      test("rejects an ID token with any cty header, indicating nested signing (RFC 7519 §7.2 step 8)") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          val jws = mock.idToken(extraHeaders = mapOf("cty" to "JWT"))

          rejectionReason(mock, federation, jws) shouldContain "cty"
        }
      }

      test("rejects a Federation Master entity statement with a crit header (A_27802-03)") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(
              FEDMASTER_STATEMENT,
              mock.fedmasterKey.sign(
                  mock.defaultFedmasterStatementBody(),
                  extraHeaders = mapOf("crit" to listOf("x-custom-ext"), "x-custom-ext" to "value"),
              ),
          )

          rejectionReason(mock, federation, mock.idToken()) shouldContain "crit"
        }
      }
    }

    context("resolveEndpoints — discovery off the verified entity statement (A_29660)") {
      test("returns the endpoints the SekIDP publishes") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          val endpoints = federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().resolveEndpoints().shouldBeRight()

          endpoints.pushedAuthorizationRequestEndpoint shouldBe mock.parEndpoint
          endpoints.authorizationEndpoint shouldBe mock.authorizationEndpoint
          endpoints.tokenEndpoint shouldBe mock.tokenEndpoint
        }
      }

      test("rejects an entity statement that is not signed by the vouched federation key") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(IDP_STATEMENT, mock.protocolKey.sign(mock.defaultIdpStatementBody()))

          federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().resolveEndpoints().shouldBeLeft().message shouldContain "SekIDP entity statement"
        }
      }
    }

    context("key rotation (A_22861)") {
      test("reloads the SekIDP's documents when the ID token names a kid it has not published yet") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          val sekIdp = federation.sekIdp(mock.sekIdpIssuer).shouldBeRight()
          sekIdp.verifyIdToken(mock.idToken()).shouldBeRight()

          val rotatedKey = FederationKey("idp-protocol-sig-2")
          mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody() + ("keys" to listOf(rotatedKey.publicJwk))))

          sekIdp.verifyIdToken(mock.idToken(key = rotatedKey)).shouldBeRight().path("sub").asText() shouldBe "mock-subject"
          // A_22861 names both documents.
          mock.callsTo(IDP_STATEMENT) shouldBe 2
          mock.callsTo(SIGNED_JWKS) shouldBe 2
        }
      }

      test("reloads at most once, so a made-up kid cannot drive repeated fetches") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          rejectionReason(mock, federation, mock.idToken(kid = "unknown-kid")) shouldContain "unknown kid »unknown-kid«"

          mock.callsTo(SIGNED_JWKS) shouldBe 2
        }
      }

      test("does not reload when a published kid carries a signature that does not verify") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          // Same kid, other key: a forgery, not a rotation.
          rejectionReason(mock, federation, mock.idToken(key = FederationKey(mock.protocolKey.kid))) shouldContain "has an invalid signature"

          mock.callsTo(SIGNED_JWKS) shouldBe 1
        }
      }
    }

    context("vouching (A_29660)") {
      test("does not touch the SekIDP's own address before the Federation Master has vouched for it") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          mock.serve(FEDMASTER_FETCH, """{"error":"not_found"}""", status = 404)

          federation.sekIdp(mock.sekIdpIssuer).shouldBeLeft().message shouldContain "is not a JWS"
          mock.callsTo(IDP_STATEMENT) shouldBe 0
        }
      }
    }

    context("caching") {
      test("stops trusting the signed JWK set once its own exp has passed") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)
          // Shorter than MAX_CACHE_SECONDS, so only exp ends the caching.
          mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody() + ("exp" to Time.currentTime() + 30)))
          val sekIdp = federation.sekIdp(mock.sekIdpIssuer).shouldBeRight()
          sekIdp.verifyIdToken(mock.idToken()).shouldBeRight()

          try {
            Time.setOffset(60)
            // The refetch has to find a valid document.
            mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody()))
            sekIdp.verifyIdToken(mock.idToken()).shouldBeRight()
          } finally {
            Time.setOffset(0)
          }

          mock.callsTo(SIGNED_JWKS) shouldBe 2
          // Nothing else in the chain is refetched.
          mock.callsTo(IDP_STATEMENT) shouldBe 1
        }
      }

      test("caches the signed JWK set although it carries no exp of its own") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          // Real signed JWK sets carry no exp; only MAX_CACHE_SECONDS bounds them.
          mock.serve(SIGNED_JWKS, mock.federationKey.sign(mock.defaultSignedJwksBody() - "exp"))
          val sekIdp = federation.sekIdp(mock.sekIdpIssuer).shouldBeRight()

          sekIdp.verifyIdToken(mock.idToken()).shouldBeRight()
          sekIdp.verifyIdToken(mock.idToken()).shouldBeRight()

          mock.callsTo(SIGNED_JWKS) shouldBe 1
        }
      }

      test("a second verification resolves the trust chain from the cache") {
        FederationMock().use { mock ->
          val federation = federationFor(mock)

          federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().verifyIdToken(mock.idToken()).shouldBeRight()
          federation.sekIdp(mock.sekIdpIssuer).shouldBeRight().verifyIdToken(mock.idToken()).shouldBeRight()

          // Cannot catch a double resolution within one verification; the cache absorbs it.
          mock.callsTo(FEDMASTER_STATEMENT) shouldBe 1
          mock.callsTo(FEDMASTER_FETCH) shouldBe 1
          mock.callsTo(IDP_STATEMENT) shouldBe 1
          mock.callsTo(SIGNED_JWKS) shouldBe 1
        }
      }
    }
  }

  /** A [Federation] pointed at [mock]; nothing is fetched before the first [Federation.sekIdp] call. */
  private fun federationFor(mock: FederationMock): Federation {
    val httpClientProvider =
        mockk<HttpClientProvider>().also {
          every { it.httpClient } returns httpClient
          every { it.maxConsumedResponseSize } returns HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE
        }
    val session = mockk<KeycloakSession>().also { every { it.getProvider(HttpClientProvider::class.java) } returns httpClientProvider }

    return Federation(session, mock.fedmasterUrl)
  }
}

/** Why the trust chain or the signature check rejects [jws]. */
private fun rejectionReason(mock: FederationMock, federation: Federation, jws: String): String? {
  federation.sekIdp(mock.sekIdpIssuer).map { v ->
    v.verifyIdToken(jws).onLeft { return it.message }
  }.onLeft { return it.message }

  return null
}
