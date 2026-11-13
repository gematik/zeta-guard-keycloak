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
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientRequestRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.jwk
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.nonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.gematik.zeta.zetaguard.keycloak.commons.server.message
import de.gematik.zeta.zetaguard.keycloak.commons.server.reportAuthenticationBypassAttack
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.verifySignature
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceFactory
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import org.keycloak.OAuthErrorException.INVALID_CLIENT_METADATA
import org.keycloak.jose.jwk.JWK
import org.keycloak.models.KeycloakSession

/**
 * @see [https://developer.android.com/privacy-and-security/security-key-attestation#verifying]
 */
abstract class AbstractAttestationChecker(private val session: KeycloakSession, private val nonceFactory: NonceFactory) {
  protected fun checkSignature(request: ZetaGuardOIDCClientRequestRepresentation): Either<KeycloakError, JWK> = either {
    val jwk = request.jwk.mapLeft { it.toError() }.bind()
    val publicKey = jwk.toPublicKey()
    val signature = request.signedHashPukClientSig?.fromBase64()
      ?: raise(keycloakError("No client data signature"))
    val clientData = jwk.toClientHashData(request.nonce())
    val checkSignature = publicKey.verifySignature(clientData, signature).mapLeft { it.toError() }.bind()

    ensure(checkSignature) { KeycloakError(INVALID_CLIENT_METADATA, "Invalid client data signature", BAD_REQUEST) }

    jwk
  }

  protected fun keycloakError(text: String): KeycloakError = KeycloakError(INVALID_CLIENT_METADATA, text, BAD_REQUEST)

  protected fun checkServerNonce(request: ZetaGuardOIDCClientRequestRepresentation): Either<KeycloakError, Unit> = either {
    when {
      request.nonce != null -> {
        val retrievedNonce = nonceFactory.retrieveNonce(request.nonce!!)

        ensure(retrievedNonce != null) {
          keycloakError("Invalid nonce value").also {
            session.reportAuthenticationBypassAttack(cause = it, session.clientIP ?: "Unknown")
          }
        }
      }

      else -> {
        // A_30192
        logger.warn("⚠️ nonce was null in DCR request")
      }
    }
  }
}

fun Throwable.toError(): KeycloakError = KeycloakError(INVALID_CLIENT_METADATA, message(), BAD_REQUEST)
