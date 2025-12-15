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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_PENDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_ATTESTATION_STATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CREATED_AT
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import org.keycloak.models.ClientModel
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION
import org.keycloak.protocol.oidc.OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED
import org.keycloak.services.clientregistration.ClientRegistrationContext
import org.keycloak.services.clientregistration.ClientRegistrationProvider
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy

/**
 * Setup initial state of newly created clients to "pending".
 *
 * For details, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.4
 */
class ZetaGuardClientRegistrationPolicy() : ClientRegistrationPolicy {
  override fun beforeRegister(context: ClientRegistrationContext) {}

  override fun afterRegister(context: ClientRegistrationContext, clientModel: ClientModel) {
    clientModel.setAttribute(ATTRIBUTE_ATTESTATION_STATE, ATTESTATION_STATE_PENDING)
    clientModel.setAttribute(ATTRIBUTE_CREATED_AT, currentTime().toISO8601())
    // https://ey-fp-dev.atlassian.net/browse/ZETAP-569
    clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, SAME_SESSION.name)
    clientModel.setAttribute(DPOP_BOUND_ACCESS_TOKENS, "true")
  }

  override fun beforeUpdate(context: ClientRegistrationContext, clientModel: ClientModel) {
    // not implemented
  }

  override fun afterUpdate(context: ClientRegistrationContext, clientModel: ClientModel) {
    // not implemented
  }

  override fun beforeDelete(provider: ClientRegistrationProvider, clientModel: ClientModel) {
    // not implemented
  }

  override fun beforeView(provider: ClientRegistrationProvider, clientModel: ClientModel) {
    // not implemented
  }

  override fun close() {
    // not implemented
  }
}
