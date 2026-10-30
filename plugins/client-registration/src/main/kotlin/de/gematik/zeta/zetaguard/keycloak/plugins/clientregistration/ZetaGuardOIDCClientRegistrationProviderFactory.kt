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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import org.keycloak.models.KeycloakSession
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProvider
import org.keycloak.services.clientregistration.oidc.OIDCClientRegistrationProviderFactory

/**
 * Registers [ZetaGuardOIDCClientRegistrationProvider] under the built-in provider id `openid-connect`, replacing Keycloak's stock provider via a
 * higher [order]. See the provider for the rationale (CVE-2026-15572 / ZF-0285).
 */
class ZetaGuardOIDCClientRegistrationProviderFactory : OIDCClientRegistrationProviderFactory() {
  override fun create(session: KeycloakSession) = ZetaGuardOIDCClientRegistrationProvider(OIDCClientRegistrationProvider(session))

  // MUST be overridden so the factory keeps the built-in `openid-connect` id it replaces.
  override fun getId() = ID

  override fun order(): Int = 10 // higher than Keycloak's stock OIDC provider so this one wins
}
