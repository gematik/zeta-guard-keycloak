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
package de.gematik.zeta.zetaguard.keycloak.plugins

import de.gematik.zeta.zetaguard.keycloak.commons.server.message
import de.gematik.zeta.zetaguard.keycloak.plugins.token.KeycloakValidationError
import de.gematik.zeta.zetaguard.keycloak.plugins.token.ZetaGuardTokenExchangeProvider
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import jakarta.ws.rs.core.Response.Status.fromStatusCode
import org.jboss.logging.Logger
import org.keycloak.OAuthErrorException
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_TOKEN
import org.keycloak.OAuthErrorException.SERVER_ERROR
import org.keycloak.events.Details
import org.keycloak.events.Errors
import org.keycloak.models.ClientModel
import org.keycloak.services.CorsErrorResponseException

internal val logger: Logger = Logger.getLogger(ZetaGuardTokenExchangeProvider::class.java)

internal fun exchangeError(throwable: Throwable, error: String = "token_exchange"): KeycloakValidationError =
    KeycloakValidationError(error, throwable.message(), BAD_REQUEST).also { logger.warn(it.toString(), throwable) }

internal fun invalidToken(reason: String) = KeycloakValidationError(INVALID_TOKEN, reason, BAD_REQUEST)

internal fun invalidClientSelfAssessment(reason: String) =
    KeycloakValidationError(INVALID_TOKEN, "Invalid or missing client self assessment: $reason", BAD_REQUEST)

internal fun missingClientState() = KeycloakValidationError(INVALID_CLIENT, "Missing client attestation state", BAD_REQUEST)

internal fun invalidNonce() = KeycloakValidationError(INVALID_TOKEN, "Invalid nonce value", BAD_REQUEST)

internal fun invalidSubject(telematikID: String) =
    KeycloakValidationError(INVALID_TOKEN, "Invalid subject, does not match certificate", BAD_REQUEST).also {
      logger.warn("Invalid subject, does not match certificate registration number »$telematikID«")
    }

internal fun internalError(e: Throwable) =
    KeycloakValidationError(SERVER_ERROR, e.message(), BAD_REQUEST).also { logger.error("Internal server error", e) }

internal fun ZetaGuardTokenExchangeProvider.clientDisabled(disabledTargetAudienceClient: ClientModel) =
    CorsErrorResponseException(context().cors, INVALID_CLIENT, "Targeted client ${disabledTargetAudienceClient.clientId} is disabled", BAD_REQUEST)
        .also {
          val event = context().event
          event.detail(Details.REASON, it.errorDescription)
          event.detail(Details.AUDIENCE, disabledTargetAudienceClient.clientId)
          event.error(Errors.CLIENT_DISABLED)
        }

internal fun invalidContext() = KeycloakValidationError(Errors.INVALID_CONFIG, "Could not create BrokeredIdentityContext", BAD_REQUEST)

internal fun invalidProviderModel() = KeycloakValidationError(Errors.INVALID_CONFIG, "Identity provider not found", BAD_REQUEST)

internal fun invalidGrantType() = KeycloakValidationError(OAuthErrorException.INVALID_GRANT, "Invalid grant type", BAD_REQUEST)

internal fun invalidCertificate(reason: String) = KeycloakValidationError("invalid_x5c_certificate", reason, BAD_REQUEST)

internal fun ZetaGuardTokenExchangeProvider.mapToCorsException(e: KeycloakValidationError) =
    CorsErrorResponseException(context().cors, e.error, e.errorDescription, fromStatusCode(e.statusCode)).also {
      val event = context().event
      event.detail(Details.REASON, e.errorDescription)
      event.error(e.error)
    }
