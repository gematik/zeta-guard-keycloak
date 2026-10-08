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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement

import de.gematik.zeta.zetaguard.keycloak.commons.server.MEDIA_TYPE_PROBLEM_JSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import jakarta.ws.rs.core.Response
import java.net.URI
import org.keycloak.http.HttpRequest
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakUriInfo
import org.keycloak.models.RealmModel

/**
 * The resource is the authentication gate — no request without a fitting client assertion may reach the
 * [EmailChangeHandler]. The happy path through validator and handler is covered by their own tests.
 */
class EmailChangeResourceTest :
    StringSpec({
      fun sessionMock(): KeycloakSession {
        val realmModel =
            mockk<RealmModel> {
              every { name } returns "zeta-guard"
              every { getClientByClientId(any()) } returns null
            }
        val uriInfo =
            mockk<KeycloakUriInfo> {
              every { baseUri } returns URI.create("http://localhost:8080")
              every { requestUri } returns URI.create("http://localhost:8080/realms/zeta-guard/zeta/identity/email")
            }
        val request = mockk<HttpRequest> { every { httpMethod } returns "POST" }
        val keycloakContext =
            mockk<KeycloakContext> {
              every { realm } returns realmModel
              every { uri } returns uriInfo
              every { httpRequest } returns request
            }
        return mockk<KeycloakSession> { every { context } returns keycloakContext }
      }

      "a missing Client-Assertion header is rejected with 401 popRequired before anything else runs" {
        val response = EmailChangeResource(mockk<KeycloakSession>()).changeEmail(null, EmailChangeRequest())

        response.status shouldBe 401
        response.mediaType.toString() shouldBe MEDIA_TYPE_PROBLEM_JSON
        response.entityMap()["code"] shouldBe ProblemCodes.POP_REQUIRED
      }

      "a blank Client-Assertion header is rejected with 401 popRequired" {
        val response = EmailChangeResource(mockk<KeycloakSession>()).changeEmail("  ", EmailChangeRequest())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.POP_REQUIRED
      }

      "an unparseable client assertion is rejected with 401 invalidSignature — the handler is never reached" {
        val response = EmailChangeResource(sessionMock()).changeEmail("not-a-jwt", EmailChangeRequest())

        response.status shouldBe 401
        response.entityMap()["code"] shouldBe ProblemCodes.INVALID_SIGNATURE
      }
    })

@Suppress("UNCHECKED_CAST") //
private fun Response.entityMap(): Map<String, Any> = entity as Map<String, Any>
