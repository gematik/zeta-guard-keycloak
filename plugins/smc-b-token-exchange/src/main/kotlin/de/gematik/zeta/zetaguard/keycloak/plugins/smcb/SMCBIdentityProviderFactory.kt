/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import de.gematik.zeta.zetaguard.keycloak.commons.server.SMCB_IDENTITY_PROVIDER_ID
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.oidc.OIDCIdentityProviderFactoryWrapper
import org.keycloak.broker.provider.AbstractIdentityProviderFactory
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession

/**
 * As of version 26.4.1, Keycloak does not implement external-to-internal token exchange in V2.
 *
 * We try to use as much as possible from the V2 OIDC provider implementation. For details, see https://www.keycloak.org/securing-apps/token-exchange
 */
class SMCBIdentityProviderFactory : AbstractIdentityProviderFactory<SMCBIdentityProvider>() {
  override fun getName() = "SMC-B OpenID Connect"

  override fun getId() = SMCB_IDENTITY_PROVIDER_ID

  override fun create(session: KeycloakSession, model: IdentityProviderModel) = SMCBIdentityProvider(session, OIDCIdentityProviderConfig(model))

  override fun parseConfig(session: KeycloakSession, config: String): MutableMap<String, String?> =
      OIDCIdentityProviderFactoryWrapper.parseConfig(session, config)

  override fun createConfig(): OIDCIdentityProviderConfig {
    val identityProviderConfig =
        OIDCIdentityProviderConfig().apply {
          /** See [org.keycloak.broker.oidc.OIDCIdentityProvider.preprocessFederatedIdentity] */
          isDisableNonce = true // We will handle this ourselves
        }
    return identityProviderConfig
  }
}
