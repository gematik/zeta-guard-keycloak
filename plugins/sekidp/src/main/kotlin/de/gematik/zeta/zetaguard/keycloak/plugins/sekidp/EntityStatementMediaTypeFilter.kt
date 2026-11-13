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

import de.gematik.zeta.zetaguard.keycloak.commons.server.MediaTypes
import de.gematik.zeta.zetaguard.keycloak.commons.server.OPENID_FEDERATION_ALIAS
import jakarta.ws.rs.HttpMethod
import jakarta.ws.rs.container.ContainerRequestContext
import jakarta.ws.rs.container.ContainerRequestFilter
import jakarta.ws.rs.container.ContainerResponseContext
import jakarta.ws.rs.container.ContainerResponseFilter
import jakarta.ws.rs.container.PreMatching
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.ext.Provider

// Built from type and subtype rather than MediaType.valueOf: no JAX-RS RuntimeDelegate needed outside the server.
private fun mediaType(value: String) = MediaType(value.substringBefore('/'), value.substringAfter('/'))

/** Keycloak's well-known endpoint answers a String config (our signed entity statement) with this media type. */
internal val KEYCLOAK_JWT_MEDIA_TYPE = mediaType(MediaTypes.JWT)

internal val ENTITY_STATEMENT_MEDIA_TYPE = mediaType(MediaTypes.ENTITY_STATEMENT_JWT)

private val ENTITY_STATEMENT_PATH = Regex("""^/?realms/[^/]+/\.well-known/${Regex.escape(OPENID_FEDERATION_ALIAS)}/?$""")

internal fun isEntityStatementPath(path: String?): Boolean = path != null && ENTITY_STATEMENT_PATH.matches(path)

private fun ContainerRequestContext.isEntityStatementRequest() =
    (method == HttpMethod.GET || method == HttpMethod.HEAD) && isEntityStatementPath(uriInfo.path)

/*
 * ANFTI2-1074: OpenID Federation requires the entity configuration at `.well-known/openid-federation` to be served as
 * `application/entity-statement+jwt`. Keycloak's generic well-known endpoint (RealmsResource.getWellKnown) only produces
 * `application/json` and `application/jwt`: it rejects `Accept: application/entity-statement+jwt` with 406 and labels
 * every String config `application/jwt`, with no way for a WellKnownProvider to choose its media type. The two filters
 * below correct both, for this one path only.
 */

/** Lets any Accept header reach the entity statement: the endpoint has exactly one representation. */
@Provider
@PreMatching
class EntityStatementAcceptFilter : ContainerRequestFilter {
  override fun filter(requestContext: ContainerRequestContext) {
    if (requestContext.isEntityStatementRequest()) {
      requestContext.headers.putSingle(HttpHeaders.ACCEPT, MediaTypes.JWT)
    }
  }
}

/** Serves the entity statement as `application/entity-statement+jwt` instead of Keycloak's `application/jwt`. */
@Provider
class EntityStatementContentTypeFilter : ContainerResponseFilter {
  override fun filter(requestContext: ContainerRequestContext, responseContext: ContainerResponseContext) {
    if (
        requestContext.isEntityStatementRequest() &&
            responseContext.status == 200 &&
            responseContext.mediaType?.isCompatible(KEYCLOAK_JWT_MEDIA_TYPE) == true
    ) {
      responseContext.headers.putSingle(HttpHeaders.CONTENT_TYPE, ENTITY_STATEMENT_MEDIA_TYPE)
    }
  }
}
