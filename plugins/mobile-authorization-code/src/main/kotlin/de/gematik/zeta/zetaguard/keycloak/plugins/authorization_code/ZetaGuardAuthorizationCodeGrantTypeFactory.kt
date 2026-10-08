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
package de.gematik.zeta.zetaguard.keycloak.plugins.authorization_code

import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaConfigResolver
import org.keycloak.Config
import org.keycloak.OAuth2Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeFactory

class ZetaGuardAuthorizationCodeGrantTypeFactory : OAuth2GrantTypeFactory {
  @Volatile internal var opaConfig: OPAConfig = OPAConfig()

  override fun getId() = OAuth2Constants.AUTHORIZATION_CODE // ← MUST match the built-in ID

  override fun getShortcut() = "za" // unique shortcut required: same grant id as the built-in ("ac")

  override fun order() = 10 // Higher than default provider (0)

  override fun create(session: KeycloakSession) = ZetaGuardAuthorizationCodeGrantType(opaConfig)

  override fun init(config: Config.Scope) {
    opaConfig = OpaConfigResolver.normalize(OpaConfigResolver.fromScope(config))
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // No-op
  }

  override fun close() {
    // No-op
  }
}
