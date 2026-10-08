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

import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.wellknown.WellKnownProvider
import org.keycloak.wellknown.WellKnownProviderFactory

class ZetaGuardEntityStatementProviderFactory : WellKnownProviderFactory {
  override fun create(session: KeycloakSession): WellKnownProvider? =
      if (OidcFlowSettings.isEnabled()) ZetaGuardEntityStatementProvider(session) else null

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // No-op
  }

  override fun close() {
    // No-op
  }

  override fun getId() = "zeta-guard-entity-statement"

  /** Path segment below /realms/{realm}/.well-known/ — fixed by the OpenID-Federation spec. */
  override fun getAlias() = "openid-federation"
}
