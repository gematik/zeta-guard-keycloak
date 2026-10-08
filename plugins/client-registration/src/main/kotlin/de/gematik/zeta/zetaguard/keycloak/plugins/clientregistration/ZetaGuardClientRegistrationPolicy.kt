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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.tracingProvider
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_MOBILE_BROWSER_FLOW
import jakarta.ws.rs.core.Response
import org.keycloak.OAuthErrorException.SERVER_ERROR
import org.keycloak.models.AuthenticationFlowBindings
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION
import org.keycloak.protocol.oidc.OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.clientregistration.ClientRegistrationContext
import org.keycloak.services.clientregistration.ClientRegistrationProvider
import org.keycloak.services.clientregistration.ErrorCodes.INVALID_CLIENT_METADATA
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy

/**
 * Setup initial state of newly created clients.
 *
 * For details, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.4
 */
class ZetaGuardClientRegistrationPolicy(
    private val dataService: ZetaGuardDataService,
    private val integrityProviderService: IntegrityProviderService,
) : ClientRegistrationPolicy {
  override fun beforeRegister(context: ClientRegistrationContext) {
    tagRequestMethod(context.session)

    if (integrityProviderService.isIntegrityProviderEnabled() && !integrityProviderService.isIntegrityProviderRunning()) {
      throw ErrorResponseException(
          SERVER_ERROR,
          "Integrity provider is not (yet) running",
          Response.Status.SERVICE_UNAVAILABLE
      ).also { SecurityEventLogger.logClientRegistrationFail(clientId = context.client.clientId, reason = "integrity_provider_unavailable") }
    }

    // mocked attestation validation for mobile clients
    if (detectAuthMethod(context.client.redirectUris) == ClientAuthMethod.SEK_IDP && !isMobileAttestationValid()) {
      throw ErrorResponseException(
          INVALID_CLIENT_METADATA,
          "Client attestation failed",
          Response.Status.BAD_REQUEST
      ).also { SecurityEventLogger.logClientRegistrationFail(clientId = context.client.clientId, reason = "attestation_failed") }
    }
  }

  override fun afterRegister(context: ClientRegistrationContext, clientModel: ClientModel) {
    // https://ey-fp-dev.atlassian.net/browse/ZETAP-569
    clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, SAME_SESSION.name)
    clientModel.setAttribute(DPOP_BOUND_ACCESS_TOKENS, "true")

    tagInstallationId(context.session, clientModel.clientId)

    val authMethod = detectAuthMethod(clientModel.redirectUris)
    if (authMethod == ClientAuthMethod.SEK_IDP) {
      clientModel.setAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW, MOCK_MOBILE_CLIENT_STATEMENT)
      clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_ENABLED, "true")
      bindMobileBrowserFlow(clientModel)
      assignEmailBindingScopes(clientModel)
    }

    val clientData = dataService.createClientData(clientModel.clientId, authMethod)

    if (authMethod == ClientAuthMethod.SEK_IDP) {
      // Attestation already passed in beforeRegister, so the mobile registration starts out valid.
      clientData.attestationState = ClientAttestationState.VALID
    }

    SecurityEventLogger.logClientRegistered(clientId = clientModel.clientId)
  }

  private fun tagRequestMethod(session: KeycloakSession) {
    try {
      session.tracingProvider.currentSpan
          .setAttribute("http.request.method_original", session.context.httpRequest.httpMethod)
    } catch (_: Exception) {
      // Observability must never break the business flow
    }
  }

  private fun tagInstallationId(session: KeycloakSession, clientId: String) {
    try {
      session.tracingProvider.currentSpan
          .setAttribute("app.installation.id", clientId)
    } catch (_: Exception) {
      // Observability must never break the business flow
    }
  }

  private fun detectAuthMethod(redirectUris: Collection<String>?): ClientAuthMethod {
    if (!OidcFlowSettings.isEnabled()) return ClientAuthMethod.SMC_B
    return if (redirectUris.isNullOrEmpty()) ClientAuthMethod.SMC_B else ClientAuthMethod.SEK_IDP
  }
  /**
   * Attestation check of a mobile client, mocked: the attestation data of the registration request
   * (client statement, jwks, nonce) is not evaluated yet, so every mobile client passes.
   */
  private fun isMobileAttestationValid(): Boolean = true

  private fun bindMobileBrowserFlow(clientModel: ClientModel) {
    val flow = clientModel.realm.getFlowByAlias(ZETA_MOBILE_BROWSER_FLOW)
      ?: throw IllegalStateException("Browser flow '$ZETA_MOBILE_BROWSER_FLOW' not found.")
    clientModel.setAuthenticationFlowBindingOverride(AuthenticationFlowBindings.BROWSER_BINDING, flow.id)
  }

  private fun assignEmailBindingScopes(clientModel: ClientModel) {
    listOf(SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION).forEach { name ->
      val scope = KeycloakModelUtils.getClientScopeByName(clientModel.realm, name)
        ?: throw IllegalStateException("Client scope '$name' not found.")
      clientModel.addClientScope(scope, false)
    }
  }

  override fun beforeUpdate(context: ClientRegistrationContext, clientModel: ClientModel) {
    // No-op
  }

  override fun afterUpdate(context: ClientRegistrationContext, clientModel: ClientModel) {
    // No-op
  }

  override fun beforeDelete(provider: ClientRegistrationProvider, clientModel: ClientModel) {
    // No-op
  }

  override fun beforeView(provider: ClientRegistrationProvider, clientModel: ClientModel) {
    // No-op
  }

  override fun close() {
    // No-op
  }
}
