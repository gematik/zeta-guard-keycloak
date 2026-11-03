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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkStatic
import io.mockk.unmockkStatic
import io.mockk.verify
import java.security.cert.CertificateException
import java.time.Instant
import org.keycloak.http.HttpRequest
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserProvider
import org.keycloak.services.x509.X509ClientCertificateLookup

private const val KVNR = "X110411675"
private const val HASHED_KVNR = "spicy-hash-of-kvnr"
private const val UNKNOWN_KVNR = "X999999999"
private const val EMAIL = "alice@example.de"
private const val ENCODING_UTIL = "de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt"

/**
 * The resource server authenticates with its mTLS client certificate (401 otherwise, without a body); the email is released only if set and verified,
 * everything else is an undifferentiated 404 without a body.
 */
class UserInfoEmailResourceTest :
    StringSpec({
      val ca = TestCa("Resource Server CA")
      val validator = ResourceServerCertificateValidator(setOf(ca.certificate))
      val trustedChain = arrayOf(ca.issueLeaf("resource-server"))

      lateinit var user: UserModel
      lateinit var lookup: X509ClientCertificateLookup
      lateinit var session: KeycloakSession
      lateinit var users: UserProvider

      beforeTest {
        mockkStatic(ENCODING_UTIL)
        every { KVNR.toSpicyHash() } returns HASHED_KVNR
        every { UNKNOWN_KVNR.toSpicyHash() } returns "unknown"

        val realm = mockk<RealmModel>()
        val request = mockk<HttpRequest>()
        user =
            mockk<UserModel> {
              every { email } returns EMAIL
              every { isEmailVerified } returns true
            }
        lookup = mockk<X509ClientCertificateLookup> { every { getCertificateChain(request) } returns trustedChain }

        users =
            mockk<UserProvider> {
              every { getUserByUsername(realm, HASHED_KVNR) } returns user
              every { getUserByUsername(realm, "unknown") } returns null
            }
        val keycloakContext =
            mockk<KeycloakContext> {
              every { this@mockk.realm } returns realm
              every { httpRequest } returns request
            }
        session =
            mockk<KeycloakSession> {
              every { context } returns keycloakContext
              every { users() } returns users
              every { getProvider(X509ClientCertificateLookup::class.java) } returns lookup
            }
      }

      afterTest { unmockkStatic(ENCODING_UTIL) }

      fun getEmail(id: String?, resourceValidator: ResourceServerCertificateValidator = validator) =
          UserInfoEmailResource(session, resourceValidator).getEmail(id)

      "a trusted resource server gets the verified email" {
        val response = getEmail(KVNR)

        response.status shouldBe 200
        response.entity shouldBe UserInfoEmailResponse(EMAIL)
      }

      "a chain via an intermediate CA is accepted" {
        val intermediate = TestCa("Intermediate CA", parent = ca)
        every { lookup.getCertificateChain(any()) } returns intermediate.chainOf(intermediate.issueLeaf("resource-server")).toTypedArray()

        getEmail(KVNR).status shouldBe 200
      }

      "without a client certificate the answer is 401 without a body" {
        every { lookup.getCertificateChain(any()) } returns null

        val response = getEmail(KVNR)

        response.status shouldBe 401
        response.entity shouldBe null
      }

      "without an x509cert-lookup provider the answer is 401" {
        every { session.getProvider(X509ClientCertificateLookup::class.java) } returns null

        getEmail(KVNR).status shouldBe 401
      }

      "a failing certificate lookup is answered with 401" {
        every { lookup.getCertificateChain(any()) } throws CertificateException("garbled header")

        getEmail(KVNR).status shouldBe 401
      }

      "a certificate of a foreign CA is answered with 401" {
        every { lookup.getCertificateChain(any()) } returns arrayOf(TestCa("Foreign CA").issueLeaf("resource-server"))

        getEmail(KVNR).status shouldBe 401
      }

      "an expired certificate is answered with 401" {
        val expired = ca.issueLeaf("resource-server", validFrom = Instant.now().minusSeconds(7200), validUntil = Instant.now().minusSeconds(3600))
        every { lookup.getCertificateChain(any()) } returns arrayOf(expired)

        getEmail(KVNR).status shouldBe 401
      }

      "without a truststore every request is answered with 401" { getEmail(KVNR, ResourceServerCertificateValidator(emptySet())).status shouldBe 401 }

      "authentication comes first: an unauthenticated request for a missing id is 401, not 404" {
        every { lookup.getCertificateChain(any()) } returns null

        getEmail(null).status shouldBe 401
      }

      "a missing or blank id is answered with 404 without a body" {
        listOf(null, "", "  ").forEach { id ->
          val response = getEmail(id)

          response.status shouldBe 404
          response.entity shouldBe null
        }
      }

      "a malformed KVNR is answered with 404 without looking up a user" {
        listOf("x110411675", "X11041167", "X1104116755", "1104116755", "XX10411675", " X110411675", "X110411675 ").forEach { kvnr ->
          val response = getEmail(kvnr)

          response.status shouldBe 404
          response.entity shouldBe null
        }

        verify(exactly = 0) { users.getUserByUsername(any(), any()) }
      }

      "an unknown user is answered with 404" { getEmail(UNKNOWN_KVNR).status shouldBe 404 }

      "a user without email is answered with 404" {
        every { user.email } returns null

        getEmail(KVNR).status shouldBe 404
      }

      "an unverified email is not released" {
        every { user.isEmailVerified } returns false

        val response = getEmail(KVNR)

        response.status shouldBe 404
        response.entity shouldBe null
      }
    })
