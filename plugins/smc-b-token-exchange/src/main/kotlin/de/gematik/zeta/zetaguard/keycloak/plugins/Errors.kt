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
package de.gematik.zeta.zetaguard.keycloak.plugins

import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.message
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.KeycloakValidationError
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.ZetaGuardTokenExchangeProvider
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import jakarta.ws.rs.core.Response.Status.FORBIDDEN
import jakarta.ws.rs.core.Response.Status.SERVICE_UNAVAILABLE
import java.security.SignatureException
import org.jboss.logging.Logger
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_GRANT
import org.keycloak.OAuthErrorException.INVALID_TOKEN
import org.keycloak.OAuthErrorException.SERVER_ERROR
import org.keycloak.OAuthErrorException.TEMPORARILY_UNAVAILABLE
import org.keycloak.events.Details
import org.keycloak.events.Errors
import org.keycloak.events.EventBuilder
import org.keycloak.models.ClientModel
import org.keycloak.representations.idm.OAuth2ErrorRepresentation
import org.keycloak.services.CorsErrorResponseException
import org.keycloak.services.cors.Cors

internal val logger: Logger = Logger.getLogger(ZetaGuardTokenExchangeProvider::class.java)

internal const val RETRY_AFTER_SECONDS = 30

internal const val HSM_UNAVAILABLE_FQCN = "de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning.HsmUnavailableException"

internal fun exchangeError(throwable: Throwable, error: String = "token_exchange"): KeycloakValidationError =
    KeycloakValidationError(error, throwable.message(), FORBIDDEN).also { logger.warn(it.toString(), throwable) }

/**
 * Token signing failed because the HSM is unreachable (cold-start guard throws `HsmUnavailableException`, or mid-flight `SignatureException` from the
 * HSM JCE provider). Returns a generic 503 with [TEMPORARILY_UNAVAILABLE]; the detailed cause stays in server logs and the Keycloak event.
 */
internal fun tokenSigningUnavailable(throwable: Throwable): KeycloakValidationError =
    KeycloakValidationError(TEMPORARILY_UNAVAILABLE, "Token signing temporarily unavailable", SERVICE_UNAVAILABLE).also {
      logger.warn(it.toString(), throwable)
    }

/** True if the cause chain (≤10 deep) contains a token-signing failure originating from the HSM path. */
internal fun hasSigningFailureCause(t: Throwable): Boolean =
    generateSequence(t as Throwable?) { it.cause }.take(10).any { it is SignatureException || it.javaClass.name == HSM_UNAVAILABLE_FQCN }

internal fun invalidToken(reason: String) =
    KeycloakValidationError(INVALID_TOKEN, reason, FORBIDDEN)

internal fun invalidTPMQuote(reason: String) = KeycloakValidationError("Invalid TPM quote", reason, FORBIDDEN)

internal fun invalidClientClaim(reason: String) =
    KeycloakValidationError(INVALID_TOKEN, "Invalid or missing client claim: »$reason«", BAD_REQUEST)

internal fun invalidClientAttestation(reason: String) = KeycloakValidationError("Invalid client attestation", reason, FORBIDDEN)

internal fun invalidClientPublicKey(reason: String) =
    KeycloakValidationError(INVALID_TOKEN, "Cannot verify client public key: »$reason«", FORBIDDEN)

internal fun missingClientState() = KeycloakValidationError(INVALID_CLIENT, "Missing client attestation state", FORBIDDEN)

internal fun missingClientData(clientId: String) = KeycloakValidationError(INVALID_CLIENT, "Could not find client data for »${clientId}«", FORBIDDEN)

internal fun invalidNonce() =
    KeycloakValidationError(INVALID_TOKEN, "Invalid nonce value", FORBIDDEN)

internal fun invalidSubject() =
    KeycloakValidationError(
        INVALID_TOKEN,
        "Invalid subject, does not match certificate registration number",
        FORBIDDEN,
    )
        .also {
          logger.warn("⚠️ Invalid subject, does not match certificate registration number")
        }

internal fun internalError(e: Throwable) =
    KeycloakValidationError(SERVER_ERROR, e.message(), FORBIDDEN).also { logger.error("💣 Internal server error", e) }

internal fun ZetaGuardTokenExchangeProvider.clientDisabled(disabledTargetAudienceClient: ClientModel) =
    CorsErrorResponseException(context().cors, INVALID_CLIENT, "Targeted client »${disabledTargetAudienceClient.clientId}« is disabled", FORBIDDEN)
        .also {
          val event = context().event
          event.detail(Details.REASON, it.errorDescription)
          event.detail(Details.AUDIENCE, disabledTargetAudienceClient.clientId)
          event.error(Errors.CLIENT_DISABLED)
        }

internal fun invalidContext() = KeycloakValidationError(Errors.INVALID_CONFIG, "Could not create BrokeredIdentityContext", FORBIDDEN)

internal fun invalidProviderModel() = KeycloakValidationError(Errors.INVALID_CONFIG, "Identity provider not found", FORBIDDEN)

internal fun invalidGrantType() =
    KeycloakValidationError(INVALID_GRANT, "Invalid grant type", FORBIDDEN)

internal fun invalidCertificate(reason: String) = KeycloakValidationError("invalid_x5c_certificate", reason, FORBIDDEN)

internal fun invalidTpmCertificate(reason: String) = KeycloakValidationError("Invalid TPM certificate chain", reason, FORBIDDEN)

internal fun logInvalidAuthorizationCodes(error: KeycloakValidationError) {
  when (error.error) {
    INVALID_GRANT -> SecurityEventLogger.logInvalidAuthorizationCode(reason = error.errorDescription)
    INVALID_TOKEN -> SecurityEventLogger.logInvalidAuthorizationCode(reason = error.errorDescription)
  }
}

fun mapToCorsException(e: KeycloakValidationError, cors: Cors, event: EventBuilder): WebApplicationException {
  val builder = Response.status(e.statusCode).entity(OAuth2ErrorRepresentation(e.error, e.errorDescription)).type(MediaType.APPLICATION_JSON_TYPE)
  if (e.statusCode == SERVICE_UNAVAILABLE.statusCode) {
    builder.header("Retry-After", RETRY_AFTER_SECONDS.toString())
  }
  event.detail(Details.REASON, e.errorDescription)
  event.error(e.error)
  return WebApplicationException(cors.add(builder))
}
