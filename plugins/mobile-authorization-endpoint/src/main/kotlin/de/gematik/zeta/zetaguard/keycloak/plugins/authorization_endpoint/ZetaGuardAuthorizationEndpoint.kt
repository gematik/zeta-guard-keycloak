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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_MOBILE_BROWSER_FLOW
import jakarta.ws.rs.core.Response
import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.LoginProtocol
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint
import org.keycloak.sessions.AuthenticationSessionModel

/**
 * Keycloak's authorization endpoint, minus one redirect for `zeta-mobile` clients.
 */
class ZetaGuardAuthorizationEndpoint(session: KeycloakSession, event: EventBuilder) : AuthorizationEndpoint(session, event) {

  override fun handleBrowserAuthenticationRequest(
      authSession: AuthenticationSessionModel,
      protocol: LoginProtocol,
      isPassive: Boolean,
      redirectToAuthentication: Boolean,
  ): Response =
      super.handleBrowserAuthenticationRequest(authSession, protocol, isPassive, redirectToAuthentication && !isBoundToMobileFlow(authSession))

  /** True when the browser flow Keycloak resolves for this authentication session is the `zeta-mobile` flow. */
  private fun isBoundToMobileFlow(authSession: AuthenticationSessionModel): Boolean =
      getAuthenticationFlow(authSession).alias == ZETA_MOBILE_BROWSER_FLOW
}
