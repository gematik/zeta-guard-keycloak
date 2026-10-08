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
import org.keycloak.services.Urls

/** Name of the assertion header of the client-management API ([zeta-guard-client-management], A_30101). */
const val CLIENT_ASSERTION_HEADER = "Client-Assertion"

/**
 * JAX-RS sub-resource for `POST /realms/{realm}/zeta/identity/email`, mounted via a sub-resource locator in
 * [ZetaEmailBindingResourceProvider] (the owner of the `zeta` realm-resource id — one factory per id).
 *
 * This HTTP layer is the authentication gate: it states explicitly what the client assertion must be bound to and
 * rejects the request if the assertion is missing or does not fit (A_30101). Only an authenticated client reaches
 * the domain checks in [EmailChangeHandler].
 */
class EmailChangeResource(private val session: KeycloakSession) {

  @POST
  @Consumes(MediaType.APPLICATION_JSON)
  @Produces(MediaType.APPLICATION_JSON)
  fun changeEmail(@HeaderParam(CLIENT_ASSERTION_HEADER) clientAssertion: String?, request: EmailChangeRequest?): Response {
    if (clientAssertion.isNullOrBlank()) {
      return problem(
          Response.Status.UNAUTHORIZED,
          ProblemCodes.POP_REQUIRED,
          "Client assertion required",
          "Email change must be authorized by possession of the registered instance key F2 (»$CLIENT_ASSERTION_HEADER« header, A_30101)",
      )
    }

    val context = session.context

    // Resolve the addressed client — the client_id from the assertion is only a non-secret selector (A_30101);
    // trust is established by the validation below.
    val clientId = ClientAssertionValidator.unverifiedClientId(clientAssertion)
    val client = clientId?.let { context.realm.getClientByClientId(it) }
    if (client == null || !client.isEnabled) {
      return problem(Response.Status.UNAUTHORIZED, ProblemCodes.INVALID_SIGNATURE, "Client assertion rejected", "Unknown or disabled client")
    }

    val validator =
        ClientAssertionValidator(
            session,
            ClientAssertionValidator.defaultChecks(
                expectedAudience = Urls.realmIssuer(context.uri.baseUri, context.realm.name),
                expectedHttpMethod = context.httpRequest.httpMethod,
                expectedTargetUri = context.uri.requestUri,
            ),
        )
    when (val outcome = validator.validate(clientAssertion, client)) {
      is ClientAssertionResult.Invalid -> return problem(outcome.status, outcome.code, "Client assertion rejected", outcome.detail)
      is ClientAssertionResult.Valid -> Unit
    }

    return EmailChangeHandler(
        session,
        ZetaGuardDataService(DefaultEMCreator(session))
    ).handle(client, request)
  }
}
