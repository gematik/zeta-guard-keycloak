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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.OPTIONS
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.ClientRegistrationProvider
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProvider

/**
 * Keycloak's OIDC dynamic client registration, with the RFC 7592 client-configuration resource
 * endpoints removed: only preflight, create (POST) and read (GET) are exposed; update (PUT) and
 * delete (DELETE) are intentionally dropped.
 *
 * Companion to [ZetaGuardDefaultClientRegistrationProvider]: closes the same RFC 7592 update/delete
 * surface on the `openid-connect` endpoint for parity (CVE-2026-15572 / ZF-0285). ZETA registers
 * clients once and does not use RFC 7592 update/delete.
 *
 * Every retained method delegates to the wrapped Keycloak provider.
 */
class ZetaGuardOIDCClientRegistrationProvider(private val delegate: OIDCClientRegistrationProvider) :
    ClientRegistrationProvider by delegate {

  @OPTIONS fun preflight(): Response = delegate.preflight()

  @OPTIONS @Path("{clientId}") fun preflightClient(): Response = preflight()

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun createOIDC(clientOIDC: OIDCClientRepresentation): Response = delegate.createOIDC(clientOIDC)

  @GET
  @Path("{clientId}")
  @Produces(MediaType.APPLICATION_JSON)
  fun getOIDC(@PathParam("clientId") clientId: String): Response = delegate.getOIDC(clientId)

  // RFC 7592 update (PUT {clientId}) and delete (DELETE {clientId}) are intentionally not exposed —
  // see the class documentation (CVE-2026-15572 / ZF-0285).
}
