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
package de.gematik.zeta.zetaguard.keycloak.plugins.authorization_endpoint

import jakarta.ws.rs.Path
import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.oidc.OIDCLoginProtocolService

/** Keycloak's OIDC protocol resource with `/auth` served by [ZetaGuardAuthorizationEndpoint], every other sub-path is inherited. */
class ZetaGuardOidcLoginProtocolService(private val session: KeycloakSession, private val event: EventBuilder) : OIDCLoginProtocolService(session, event) {

  @Path("auth")
  override fun auth(): Any = ZetaGuardAuthorizationEndpoint(session, event)
}
