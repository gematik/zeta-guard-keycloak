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
import de.gematik.zeta.zetaguard.keycloak.commons.server.MediaTypes
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.MultivaluedHashMap
import jakarta.ws.rs.core.MultivaluedMap

private const val ENTITY_STATEMENT_PATH = "/realms/zeta-guard/.well-known/openid-federation"

private fun request(path: String, method: String = "GET", accept: String? = null): ContainerRequestContext {
  val headers = MultivaluedHashMap<String, String>().apply { accept?.let { putSingle(HttpHeaders.ACCEPT, it) } }
  return mockk {
    every { this@mockk.method } returns method
    every { uriInfo.path } returns path
    every { this@mockk.headers } returns headers
  }
}

private fun response(status: Int, mediaType: MediaType?): Pair<ContainerResponseContext, MultivaluedMap<String, Any>> {
  val headers = MultivaluedHashMap<String, Any>().apply { mediaType?.let { putSingle(HttpHeaders.CONTENT_TYPE, it) } }
  val context =
      mockk<ContainerResponseContext> {
        every { this@mockk.status } returns status
        every { this@mockk.mediaType } returns mediaType
        every { this@mockk.headers } returns headers
      }
  return context to headers
}

class EntityStatementMediaTypeFilterTest : ZetaGuardFunSpec() {
  init {
    test("matches the entity statement path of any realm, with or without leading or trailing slash") {
      isEntityStatementPath(ENTITY_STATEMENT_PATH) shouldBe true
      isEntityStatementPath("realms/other/.well-known/openid-federation") shouldBe true
      isEntityStatementPath("/realms/zeta-guard/.well-known/openid-federation/") shouldBe true
    }

    test("does not match other well-known aliases, sub paths or other locations") {
      isEntityStatementPath("/realms/zeta-guard/.well-known/openid-configuration") shouldBe false
      isEntityStatementPath("/realms/zeta-guard/.well-known/openid-federation-x") shouldBe false
      isEntityStatementPath("/realms/zeta-guard/.well-known/openid-federation/x") shouldBe false
      isEntityStatementPath("/realms/a/b/.well-known/openid-federation") shouldBe false
      isEntityStatementPath("/.well-known/openid-federation") shouldBe false
      isEntityStatementPath(null) shouldBe false
    }

    test("ANFTI2-1074: Accept application/entity-statement+jwt is rewritten to what Keycloak produces") {
      val request = request(ENTITY_STATEMENT_PATH, accept = MediaTypes.ENTITY_STATEMENT_JWT)

      EntityStatementAcceptFilter().filter(request)

      request.headers shouldContain (HttpHeaders.ACCEPT to listOf(MediaTypes.JWT))
    }

    test("Accept is left alone on other paths and for other methods") {
      val other = request("/realms/zeta-guard/.well-known/openid-configuration", accept = MediaTypes.ENTITY_STATEMENT_JWT)
      val post = request(ENTITY_STATEMENT_PATH, method = "POST", accept = MediaTypes.ENTITY_STATEMENT_JWT)

      EntityStatementAcceptFilter().filter(other)
      EntityStatementAcceptFilter().filter(post)

      other.headers shouldContain (HttpHeaders.ACCEPT to listOf(MediaTypes.ENTITY_STATEMENT_JWT))
      post.headers shouldContain (HttpHeaders.ACCEPT to listOf(MediaTypes.ENTITY_STATEMENT_JWT))
    }

    test("ANFTI2-1074: a successful entity statement response is served as application/entity-statement+jwt") {
      val (response, headers) = response(200, KEYCLOAK_JWT_MEDIA_TYPE)

      EntityStatementContentTypeFilter().filter(request(ENTITY_STATEMENT_PATH), response)

      headers shouldContain (HttpHeaders.CONTENT_TYPE to listOf(ENTITY_STATEMENT_MEDIA_TYPE))
    }

    test("error responses and other paths keep their Content-Type") {
      val (notFound, notFoundHeaders) = response(404, MediaType.APPLICATION_JSON_TYPE)
      val (other, otherHeaders) = response(200, KEYCLOAK_JWT_MEDIA_TYPE)

      EntityStatementContentTypeFilter().filter(request(ENTITY_STATEMENT_PATH), notFound)
      EntityStatementContentTypeFilter().filter(request("/realms/zeta-guard/.well-known/jwt-vc-issuer"), other)

      notFoundHeaders shouldContain (HttpHeaders.CONTENT_TYPE to listOf(MediaType.APPLICATION_JSON_TYPE))
      otherHeaders shouldContain (HttpHeaders.CONTENT_TYPE to listOf(KEYCLOAK_JWT_MEDIA_TYPE))
    }
  }
}
