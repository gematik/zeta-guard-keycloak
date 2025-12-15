/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.nonce

import jakarta.ws.rs.GET
import jakarta.ws.rs.HttpMethod
import jakarta.ws.rs.OPTIONS
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession
import org.keycloak.services.cors.Cors
import org.keycloak.services.resource.RealmResourceProvider
import org.keycloak.services.util.CacheControlUtil

/**
 * Nonce provider REST endpoint under .../realms/zeta-guard/zeta-guard-nonce
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5.1
 */
class NonceProvider(private val session: KeycloakSession, private val nonceFactory: NonceFactory) : RealmResourceProvider {
  @OPTIONS
  @Path("{any:.*}")
  fun preflight(): Response =
      Cors.builder().allowedMethods(HttpMethod.GET).preflight().auth().add(Response.ok().cacheControl(CacheControlUtil.noCache()))

  @GET
  @Path("")
  @Produces(MediaType.TEXT_PLAIN)
  fun createNonce(): Response {
    val address = session.context.connection?.remoteAddr ?: "<unknown>"
    val value = nonceFactory.createNonce(address).nonceValue

    return Response.ok().entity(value).build()
  }

  override fun getResource() = this

  override fun close() {}
}
