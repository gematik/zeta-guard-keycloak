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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.oidc

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.asMap
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientResponseRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_REGISTRATION_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.registrationState
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.DELETE
import jakarta.ws.rs.GET
import jakarta.ws.rs.OPTIONS
import jakarta.ws.rs.POST
import jakarta.ws.rs.PUT
import jakarta.ws.rs.Path
import jakarta.ws.rs.PathParam
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.ClientRegistrationProvider
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProvider

/**
 * Keycloak's OIDC dynamic client registration, extended with the registration's status (A_30086).
 *
 * Every override delegates to `super` and only re-wraps the entity.
 */
class ZetaGuardOIDCClientRegistrationProvider(
    private val dataService: ZetaGuardDataService,
    private val delegate: OIDCClientRegistrationProvider,
    private val session: KeycloakSession
) :
  ClientRegistrationProvider by delegate {

  @OPTIONS
  fun preflight(): Response = delegate.preflight()

  @OPTIONS
  @Path("{clientId}")
  fun preflightClient(): Response = preflight()

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun createOIDC(clientOIDC: ZetaGuardOIDCClientRequestRepresentation): Response {
    session.setAttribute(ATTRIBUTE_CLIENT_REGISTRATION_DATA, clientOIDC)

    return delegate.createOIDC(clientOIDC).withRegistrationState()
  }

  @GET
  @Path("{clientId}")
  @Produces(MediaType.APPLICATION_JSON)
  fun getOIDC(clientId: String): Response = delegate.getOIDC(clientId).withRegistrationState()

  @PUT
  @Path("{clientId}")
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun updateOIDC(clientId: String, clientOIDC: OIDCClientRepresentation): Response =
      delegate.updateOIDC(clientId, clientOIDC).withRegistrationState()

  @DELETE
  @Path("{clientId}")
  fun deleteOIDC(@PathParam("clientId") clientId: String): Response = delegate.deleteOIDC(clientId)

  private fun Response.withRegistrationState(): Response = Response.fromResponse(this).entity(addRegistrationState(entity, dataService)).build()
}

/**
 * Copies [entity] into a [ZetaGuardOIDCClientResponseRepresentation] and sets its [ZetaGuardOIDCClientResponseRepresentation.status] from the stored registration
 * data (A_30086).
 *
 * When there is no registration data or when the registration has no status because its attestation is not valid, status stays null and the member is
 * absent from the JSON: the response is serialized by Keycloak's own `ObjectMapperResolver`, which is configured `NON_NULL`. [asMap]/[toObject] only
 * build the in-memory copy.
 */
internal fun addRegistrationState(entity: Any?, dataService: ZetaGuardDataService): Any? =
    if (entity is OIDCClientRepresentation) {
      entity.asMap().toObject<ZetaGuardOIDCClientResponseRepresentation>().apply {
        status = clientId?.let { dataService.findClientData(it) }?.registrationState()
      }
    } else entity
