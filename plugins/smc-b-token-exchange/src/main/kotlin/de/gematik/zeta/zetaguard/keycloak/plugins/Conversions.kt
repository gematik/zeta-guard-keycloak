/*-
 * #%L
 * referencevalidator-cli
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

import arrow.core.Either
import arrow.core.Either.Companion.catch
import arrow.core.raise.either
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.server.AttackDetectionLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.CapecAttackMechanics
import de.gematik.zeta.zetaguard.keycloak.commons.server.baseUrl
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toJWKS
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.KeycloakValidationError
import de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange.ZetaGuardTokenExchangeContext
import jakarta.ws.rs.core.MultivaluedMap
import java.security.PublicKey
import java.security.cert.X509Certificate
import org.keycloak.OAuth2Constants.AUDIENCE
import org.keycloak.TokenVerifier
import org.keycloak.TokenVerifier.IS_ACTIVE
import org.keycloak.crypto.SignatureProvider
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.jose.jwk.JWK
import org.keycloak.protocol.oidc.OIDCConfigAttributes.JWKS_STRING
import org.keycloak.protocol.oidc.TokenManager.TokenRevocationCheck
import org.keycloak.representations.IDToken
import org.keycloak.util.TokenUtil

internal fun JWK.extractPublicKey(): Either<KeycloakValidationError, PublicKey> =
  catch { this@extractPublicKey.toPublicKey() }.mapLeft { invalidClientPublicKey("Cannot convert JWK to public key") }

internal fun String.convertToJWKS(): Either<KeycloakValidationError, JSONWebKeySet> =
  catch { this@convertToJWKS.toJWKS() }.mapLeft { invalidClientPublicKey("Cannot parse JWKS attribute »$JWKS_STRING«") }

internal inline fun <reified T> parseClaim(json: Map<String, Any>, claim: String): Either<KeycloakValidationError, T> =
  catch { json.toObject<T>() }
    .mapLeft {
      logger.warn("Failed to read $claim", it)
      invalidClientClaim(it.message ?: "Failed to read $claim")
    }

internal fun readCertificate(context: ZetaGuardTokenExchangeContext): Either<KeycloakValidationError, X509Certificate> =
  catch {
      // leaf certificate is first in chain
      context.tokenHeader.x5c[0].toCertificate()
    }
    .mapLeft { invalidToken(it.message ?: "Invalid certificate") }

internal fun createToken(verifier: TokenVerifier<IDToken>, context: ZetaGuardTokenExchangeContext): Either<KeycloakValidationError, IDToken> =
  catch { verifier.verify().getToken() }
    .mapLeft {
      logger.warn("Failed to verify identity token", it)
      AttackDetectionLogger.warnWithMDC(it, CapecAttackMechanics.AUTHENTICATION_BYPASS, context.clientIP)
      invalidToken(it.message ?: "Token validation failed")
    }

internal fun createTokenVerifier(context: ZetaGuardTokenExchangeContext): Either<KeycloakValidationError, TokenVerifier<IDToken>> = either {
  val session = context.context.session
  val expectedAudiences = session.context.uri.baseUrl()
  val actualAudiences = context.subjectToken.toAccessToken().audience.toList()

  logger.debug("Audience check: Expecting »$expectedAudiences«, subject token contains: $actualAudiences")

  catch {
      val verifier =
        TokenVerifier.create(context.subjectToken, IDToken::class.java)
          .withChecks(IS_ACTIVE)
          .withChecks(TokenRevocationCheck(session))
          .audience(expectedAudiences)
          .tokenType(listOf(TokenUtil.TOKEN_TYPE_BEARER, TokenUtil.TOKEN_TYPE_DPOP))
      val key = context.createCertificateKeyWrapper()
      val signatureProvider = session.getProvider(SignatureProvider::class.java, context.tokenHeader.algorithm.name)
      val signatureVerifier = signatureProvider.verifier(key)

      verifier.verifierContext(signatureVerifier)
    }
    .mapLeft {
      logger.warn("Failed to create verifier", it)
      invalidToken(it.message ?: "Failed to create verifier")
    }
    .bind()
}

internal fun resolveAudiences(formParams: MultivaluedMap<String, String>, context: ZetaGuardTokenExchangeContext): List<String>? {
  val audiencesRaw = formParams.getFirst(AUDIENCE)

  return if (!audiencesRaw.isNullOrBlank()) {
    audiencesRaw.split(',', ' ').map { it.trim() }.filter { it.isNotBlank() }.ifEmpty { null }
  } else {
    try {
      context.subjectToken.toAccessToken().audience?.toList()
    } catch (_: Exception) {
      null
    }
  }
}
