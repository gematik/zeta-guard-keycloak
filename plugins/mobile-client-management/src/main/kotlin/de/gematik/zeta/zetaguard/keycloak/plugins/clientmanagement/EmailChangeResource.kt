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

import arrow.core.getOrElse
import de.gematik.zeta.zetaguard.keycloak.commons.server.ProblemCodes
import de.gematik.zeta.zetaguard.keycloak.commons.server.problem
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.HeaderParam
import jakarta.ws.rs.POST
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import org.keycloak.models.KeycloakSession

/**
 * JAX-RS sub-resource for `POST /realms/{realm}/zeta/identity/email`, mounted via a sub-resource locator in
 * [ZetaEmailBindingResourceProvider] (the owner of the `zeta` realm-resource id — one factory per id).
 *
 * Reachable only through the PEP, which verifies access token, DPoP proof and scope and forwards the client data in
 * [HEADER_ZETA_CLIENT_DATA]. This layer only resolves the calling client from that client data (`client_id`); the
 * domain checks live in [EmailChangeHandler].
 */
class EmailChangeResource(private val session: KeycloakSession) {

  private val dataService = ZetaGuardDataService(DefaultEMCreator(session))
  private val pepClientDataService = PepClientDataService(dataService)

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun changeEmail(@HeaderParam(HEADER_ZETA_CLIENT_DATA) zetaClientData: String?, request: EmailChangeRequest?): Response = session.problemOnError {
    val zetaClient =
        pepClientDataService.clientFromPep(zetaClientData).mapLeft {
          problem(
              Response.Status.UNAUTHORIZED,
              ProblemCodes.UNAUTHORIZED,
              "Caller unknown",
              "Email change requires the client data forwarded by the PEP (header »zeta-client-data«)",
          )
        }.getOrElse { return it }

    session.context.realm.getClientByClientId(zetaClient.id)?.takeIf { it.isEnabled }
      ?: return problem(Response.Status.UNAUTHORIZED, ProblemCodes.UNAUTHORIZED, "Caller unknown", "Unknown or disabled client")

    EmailChangeHandler(session, dataService).handle(zetaClient, request)
  }
}
