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

import org.keycloak.Config
import org.keycloak.authentication.Authenticator
import org.keycloak.authentication.AuthenticatorFactory
import org.keycloak.models.AuthenticationExecutionModel.Requirement
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderConfigProperty

/**
 * Unlike the default redirector, this one is SekIDP-specific and has no target IDP to configure:
 * it always redirects to the one alias it's built for, so no intern keycloak redirects which uses cookies are needed.
 */
class SekIdpDirectRedirectAuthenticatorFactory : AuthenticatorFactory {

  override fun getId() = PROVIDER_ID

  override fun create(session: KeycloakSession): Authenticator = SekIdpDirectRedirectAuthenticator()

  override fun getDisplayType() = "SekIDP Direct Redirector"

  override fun getReferenceCategory(): String? = null

  override fun isConfigurable() = false

  override fun getRequirementChoices() = REQUIREMENT_CHOICES

  override fun isUserSetupAllowed() = true

  override fun getHelpText() =
      "Redirects straight to the SekIDP, skipping the cookie-bound /broker/{alias}/login round trip."

  override fun getConfigProperties(): List<ProviderConfigProperty> = emptyList()

  override fun init(config: Config.Scope) = Unit

  override fun postInit(factory: KeycloakSessionFactory) = Unit

  override fun close() = Unit

  companion object {
    const val PROVIDER_ID = "sekidp-direct-redirector"

    private val REQUIREMENT_CHOICES = arrayOf(Requirement.REQUIRED, Requirement.ALTERNATIVE, Requirement.DISABLED)
  }
}
