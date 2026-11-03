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

import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status
import org.keycloak.OAuthErrorException
import org.keycloak.representations.idm.OAuth2ErrorRepresentation

object SekIdpRedirectionError {

  /** The `state_as` mapping holds no entry. */
  fun unknownStateAs() = KeycloakError(OAuthErrorException.INVALID_REQUEST, "unknown or expired state", Status.BAD_REQUEST)

  /** A user carries the username but no Federated Identity. */
  fun identityAlreadyRegistered() = KeycloakError(OAuthErrorException.ACCESS_DENIED, "identity already registered", Status.CONFLICT)

  /** The integrity provider is enabled but not operational, so the user data of the ID token would be stored unencrypted. */
  fun integrityProviderNotRunning() =
      KeycloakError(OAuthErrorException.SERVER_ERROR, "integrity provider is not (yet) running", Status.SERVICE_UNAVAILABLE)
}

/** The one place a Redirection Endpoint failure becomes the JAX-RS response the ZETA Client receives. */
fun KeycloakError.toResponse(): Response =
    Response.status(statusCode).entity(OAuth2ErrorRepresentation(error, errorDescription)).type(MediaType.APPLICATION_JSON_TYPE).build()
