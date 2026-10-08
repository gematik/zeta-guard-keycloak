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
package de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding

import de.gematik.zeta.zetaguard.keycloak.commons.server.EMAIL_BINDING_TOKEN_EXCHANGE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaConfigResolver
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory

class ZetaGuardEmailBindingTokenExchangeProviderFactory : TokenExchangeProviderFactory {
  @Volatile internal var opaConfig: OPAConfig = OPAConfig()

  override fun create(session: KeycloakSession) = ZetaGuardEmailBindingTokenExchangeProvider(opaConfig)

  override fun getId() = EMAIL_BINDING_TOKEN_EXCHANGE_PROVIDER_ID

  // Higher priority than the SMC-B provider (30) and the standard provider (10); supports() limits
  // this provider to mobile clients, so everything else falls through to those.
  override fun order() = 40

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
