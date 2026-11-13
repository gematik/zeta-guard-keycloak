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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.PostureType
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.gematik.zeta.zetaguard.keycloak.commons.server.message
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.ZetaGuardTokenExchangeProvider
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import jakarta.ws.rs.core.Response.Status.FORBIDDEN
import jakarta.ws.rs.core.Response.Status.SERVICE_UNAVAILABLE
import java.security.SignatureException
import org.keycloak.OAuthErrorException
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

internal const val RETRY_AFTER_SECONDS = 30

internal const val HSM_UNAVAILABLE_FQCN = "de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning.HsmUnavailableException"

/**
 * Token signing failed because the HSM is unreachable (cold-start guard throws `HsmUnavailableException`, or mid-flight `SignatureException` from the
 * HSM JCE provider). Returns a generic 503 with [TEMPORARILY_UNAVAILABLE]; the detailed cause stays in server logs and the Keycloak event.
 */
internal fun tokenSigningUnavailable(throwable: Throwable): KeycloakError =
    KeycloakError(TEMPORARILY_UNAVAILABLE, "Token signing temporarily unavailable", SERVICE_UNAVAILABLE).also {
      logger.warn(it.toString(), throwable)
    }

/** True if the cause chain (≤10 deep) contains a token-signing failure originating from the HSM path. */
internal fun hasSigningFailureCause(t: Throwable): Boolean =
    generateSequence(t as Throwable?) { it.cause }.take(10).any { it is SignatureException || it.javaClass.name == HSM_UNAVAILABLE_FQCN }

internal fun invalidToken(reason: String) =
    KeycloakError(INVALID_TOKEN, reason, FORBIDDEN)

internal fun invalidGrant(reason: String) =
    KeycloakError(INVALID_GRANT, reason, BAD_REQUEST)

internal fun invalidTPMQuote(reason: String) = KeycloakError("Invalid TPM quote", reason, BAD_REQUEST)

internal fun invalidClientClaim(reason: String) =
    KeycloakError(INVALID_TOKEN, "Invalid or missing client claim: »$reason«", BAD_REQUEST)

internal fun invalidClientAttestation(reason: String) = KeycloakError("Invalid client attestation", reason, BAD_REQUEST)

internal fun invalidClientPublicKey(reason: String) =
    KeycloakError(INVALID_TOKEN, "Cannot verify client public key: »$reason«", BAD_REQUEST)

internal fun missingClientState() = KeycloakError(INVALID_CLIENT, "Missing client attestation state", BAD_REQUEST)

internal fun missingClientData(clientId: String) = KeycloakError(INVALID_CLIENT, "Could not find client data for »${clientId}«", BAD_REQUEST)

internal fun invalidNonce(type: String) = KeycloakError(INVALID_TOKEN, "Invalid nonce value for »${type}«", BAD_REQUEST)

internal fun invalidScope() =
    KeycloakError(OAuthErrorException.INVALID_SCOPE, "Invalid scope parameter", BAD_REQUEST)

internal fun invalidSubject() =
    KeycloakError(
        INVALID_TOKEN,
        "Invalid subject, does not match certificate registration number",
        FORBIDDEN,
    ).also {
      logger.warn("⚠️ Invalid subject, does not match certificate registration number")
    }

internal fun unexpectedError(e: Throwable, error: String) =
    KeycloakError(SERVER_ERROR, e.message(), BAD_REQUEST).also { logger.warn("⚠️ Unexpected error »${error}«", e) }

internal fun ZetaGuardTokenExchangeProvider.clientDisabled(disabledTargetAudienceClient: ClientModel) =
    CorsErrorResponseException(context().cors, INVALID_CLIENT, "Targeted client »${disabledTargetAudienceClient.clientId}« is disabled", FORBIDDEN)
        .also {
          val event = context().event
          event.detail(Details.REASON, it.errorDescription)
          event.detail(Details.AUDIENCE, disabledTargetAudienceClient.clientId)
          event.error(Errors.CLIENT_DISABLED)
        }

internal fun invalidContext() = KeycloakError(Errors.INVALID_CONFIG, "Could not create BrokeredIdentityContext", FORBIDDEN)

internal fun invalidProviderModel() = KeycloakError(Errors.INVALID_CONFIG, "Identity provider not found", FORBIDDEN)

internal fun invalidGrantType() =
    KeycloakError(INVALID_GRANT, "Invalid grant type", BAD_REQUEST)

internal fun invalidCertificate(reason: String) = KeycloakError("invalid_x5c_certificate", reason, BAD_REQUEST)

internal fun invalidTpmCertificate(reason: String) = KeycloakError("Invalid TPM certificate chain", reason, BAD_REQUEST)

internal fun invalidPostureType(postureType: PostureType) =
    KeycloakError("Invalid posture type", "Invalid posture type: »$postureType«", BAD_REQUEST)

internal fun logInvalidAuthorizationCodes(error: KeycloakError) {
  when (error.error) {
    INVALID_GRANT -> SecurityEventLogger.logInvalidAuthorizationCode(reason = error.errorDescription)
    INVALID_TOKEN -> SecurityEventLogger.logInvalidAuthorizationCode(reason = error.errorDescription)
  }
}

fun mapToCorsException(e: KeycloakError, cors: Cors, event: EventBuilder): WebApplicationException {
  val builder = Response.status(e.statusCode)
      .entity(OAuth2ErrorRepresentation(e.error, e.errorDescription))
      .type(MediaType.APPLICATION_JSON_TYPE)
  if (e.statusCode == SERVICE_UNAVAILABLE.statusCode) {
    builder.header("Retry-After", RETRY_AFTER_SECONDS.toString())
  }

  e.responseHeaders.forEach { (name, value) -> builder.header(name, value) }

  event.detail(Details.REASON, e.errorDescription)
  event.error(e.error)

  return WebApplicationException(cors.add(builder))
}
