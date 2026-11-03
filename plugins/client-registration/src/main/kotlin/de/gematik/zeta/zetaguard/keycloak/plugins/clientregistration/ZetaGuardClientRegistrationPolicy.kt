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

import arrow.core.Either
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.SoftwareRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_REGISTRATION_DATA
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_CLIENT_MANAGEMENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_MOBILE_BROWSER_FLOW
import de.gematik.zeta.zetaguard.keycloak.commons.server.tracingProvider
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceFactory
import de.gematik.zeta.zetaguard.keycloak.plugins.trust.TrustMaterial
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import org.keycloak.OAuthErrorException.INVALID_CLIENT_METADATA
import org.keycloak.OAuthErrorException.SERVER_ERROR
import org.keycloak.models.AuthenticationFlowBindings
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.ParConfig.REQUIRE_PUSHED_AUTHORIZATION_REQUESTS
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION
import org.keycloak.protocol.oidc.OIDCConfigAttributes.DPOP_BOUND_ACCESS_TOKENS
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED
import org.keycloak.services.ErrorResponseException
import org.keycloak.services.clientregistration.ClientRegistrationContext
import org.keycloak.services.clientregistration.ClientRegistrationProvider
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicy

/**
 * Setup initial state of newly created clients.
 *
 * For details, see https://gemspec.gematik.de/prereleases/Draft_ZETA_26_2/gemSpec_ZETA_V2.0.0_CC/#5.3.2.2
 */
class ZetaGuardClientRegistrationPolicy(
    session: KeycloakSession,
    nonceFactory: NonceFactory,
    trustMaterial: TrustMaterial,
    private val dataService: ZetaGuardDataService,
    private val integrityProviderService: IntegrityProviderService,
) : ClientRegistrationPolicy {
  private val appleAttestationChecker = AppleAttestationChecker(session, nonceFactory, trustMaterial.apple)
  private val googleAttestationChecker = GoogleAttestationChecker(
      session, nonceFactory, trustMaterial.google, trustMaterial.googleCertificateStatusService
  )
  private val softwareAttestationChecker = SoftwareAttestationChecker(session, nonceFactory)

  override fun beforeRegister(context: ClientRegistrationContext) = either {
    checkRegistration(context).bind()
  }.getOrElse {
    throw ErrorResponseException(it.error, it.errorDescription, it.status)
  }

  override fun afterRegister(context: ClientRegistrationContext, clientModel: ClientModel) {
    registerClient(clientModel, context).getOrElse { throw it }
  }

  private fun checkRegistration(context: ClientRegistrationContext): Either<KeycloakError, Unit> = either {
    tagRequestMethod(context.session)

    ensure(!integrityProviderService.isIntegrityProviderEnabled() || integrityProviderService.isIntegrityProviderRunning()) {
      KeycloakError(
          SERVER_ERROR,
          "Integrity provider is not (yet) running",
          Response.Status.SERVICE_UNAVAILABLE
      ).also { SecurityEventLogger.logClientRegistrationFail(clientId = context.client.clientId, reason = "integrity_provider_unavailable") }
    }

    if (detectAuthMethod(context.client.redirectUris) == ClientAuthMethod.SEK_IDP) {
      val clientRegistrationRequest =
          context.session.getAttribute(ATTRIBUTE_CLIENT_REGISTRATION_DATA, ZetaGuardOIDCClientRequestRepresentation::class.java)
            ?: raise(KeycloakError(INVALID_CLIENT_METADATA, "Client registration data not found", BAD_REQUEST))

      when (clientRegistrationRequest) {
        is AppleRegistrationRequest -> appleAttestationChecker.checkAppleAttestation(clientRegistrationRequest).bind()
        is AndroidRegistrationRequest -> googleAttestationChecker.checkAndroidAttestation(clientRegistrationRequest).bind()
        is SoftwareRegistrationRequest -> softwareAttestationChecker.checkSoftwareAttestation(clientRegistrationRequest).bind()
        else -> raise(
            KeycloakError(
                INVALID_CLIENT_METADATA,
                "Unsupported attestation type ${clientRegistrationRequest.attestationType}",
                BAD_REQUEST
            )
        )
      }
    }
  }

  private fun registerClient(clientModel: ClientModel, context: ClientRegistrationContext): Either<IllegalStateException, Unit> = either {
    // https://ey-fp-dev.atlassian.net/browse/ZETAP-569
    clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED, SAME_SESSION.name)
    clientModel.setAttribute(DPOP_BOUND_ACCESS_TOKENS, "true")

    tagInstallationId(context.session, clientModel.clientId)

    val authMethod = detectAuthMethod(clientModel.redirectUris)

    if (authMethod == ClientAuthMethod.SEK_IDP) {
      clientModel.setAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW, MOCK_MOBILE_CLIENT_STATEMENT)
      clientModel.setAttribute(STANDARD_TOKEN_EXCHANGE_ENABLED, "true")
      clientModel.setAttribute(REQUIRE_PUSHED_AUTHORIZATION_REQUESTS, "true")

      bindMobileBrowserFlow(clientModel).bind()
      assignMobileClientScopes(clientModel).bind()
    }

    val clientData = dataService.createClientData(clientModel.clientId, authMethod)
    val clientRegistrationRequest =
        context.session.getAttribute(ATTRIBUTE_CLIENT_REGISTRATION_DATA, ZetaGuardOIDCClientRequestRepresentation::class.java)
          ?: raise(IllegalStateException("Client registration data not found"))

    if (authMethod == ClientAuthMethod.SEK_IDP) {
      // Otherwise attestation type is set during token exchange
      clientData.attestationType = clientRegistrationRequest.attestationType

      // Attestation already passed in beforeRegister, so the mobile registration starts out valid.
      clientData.attestationState = ClientAttestationState.VALID
    }

    SecurityEventLogger.logClientRegistered(clientId = clientModel.clientId)
  }

  // Observability must never break the business flow
  private fun tagRequestMethod(session: KeycloakSession) = Either.catch {
    session.tracingProvider.currentSpan
        .setAttribute("http.request.method_original", session.context.httpRequest.httpMethod)
  }

  private fun tagInstallationId(session: KeycloakSession, clientId: String) = Either.catch {
    session.tracingProvider.currentSpan.setAttribute("app.installation.id", clientId)
  }

  private fun detectAuthMethod(redirectUris: Collection<String>?): ClientAuthMethod = when {
    !OidcFlowSettings.isEnabled() -> ClientAuthMethod.SMC_B
    redirectUris.isNullOrEmpty() -> ClientAuthMethod.SMC_B
    else -> ClientAuthMethod.SEK_IDP
  }

  private fun bindMobileBrowserFlow(clientModel: ClientModel) = either {
    val flow = clientModel.realm.getFlowByAlias(ZETA_MOBILE_BROWSER_FLOW)
      ?: raise(IllegalStateException("Browser flow »$ZETA_MOBILE_BROWSER_FLOW« not found."))

    clientModel.setAuthenticationFlowBindingOverride(AuthenticationFlowBindings.BROWSER_BINDING, flow.id)
  }

  // Client scopes of a mobile client; deliberately not realm defaults, so SMC-B clients never carry them. The e-mail
  // scopes stay optional (the reduced token is down-scoped to them), client management is a default scope so every
  // regular mobile token carries it without the app having to request it.
  private fun assignMobileClientScopes(clientModel: ClientModel) = either {
    listOf(SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION, SCOPE_CLIENT_MANAGEMENT).forEach { name ->
      val scope = KeycloakModelUtils.getClientScopeByName(clientModel.realm, name)
        ?: raise(IllegalStateException("Client scope »$name« not found."))

      clientModel.addClientScope(scope, name == SCOPE_CLIENT_MANAGEMENT)
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
