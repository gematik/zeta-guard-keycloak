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
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.Response
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession

private val logger: Logger = Logger.getLogger("de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.ProblemOnError")

/**
 * Runs [block] and turns an unexpected exception into a 500 problem: like Keycloak's own error handler, the transaction is rolled back and the error
 * logged, but the caller gets problem+json instead of an OAuth error (KeycloakErrorHandler maps every exception and replaces any response body).
 *
 * A [WebApplicationException] is an intended response and passes through. An exception raised while committing, after [block] returned, still ends
 * up in Keycloak's handler.
 */
internal inline fun KeycloakSession.problemOnError(block: () -> Response): Response =
    try {
      block()
    } catch (e: WebApplicationException) {
      throw e
    } catch (e: Exception) {
      unexpectedErrorProblem(e)
    }

internal fun KeycloakSession.unexpectedErrorProblem(e: Exception): Response {
  transactionManager.setRollbackOnly()
  logger.error("Unexpected error, rolling back the transaction", e)

  return problem(Response.Status.INTERNAL_SERVER_ERROR, ProblemCodes.INTERNAL_ERROR, "Internal error", "For more on this error consult the server log.")
}
