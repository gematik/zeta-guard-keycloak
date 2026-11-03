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
import com.webauthn4j.appattest.data.attestation.statement.AppleAppAttestAttestationStatement
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.client_attestation.APPLE_APP_ATTEST_AAGUID
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AttestationUtil.extractRawAuthenticationData
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.appleAttestationObject
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.appleAttestationStatement
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.nonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractAppleNonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toAppleKeyId
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceFactory
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import java.security.cert.X509Certificate
import org.keycloak.OAuthErrorException.INVALID_CLIENT_METADATA
import org.keycloak.jose.jwk.JWK
import org.keycloak.models.KeycloakSession

/**
 * @see [https://developer.apple.com/documentation/devicecheck/attestation-object-validation-guide]
 */
class AppleAttestationChecker(session: KeycloakSession, nonceFactory: NonceFactory, private val appleTrustStore: KeystoreService) :
  AbstractAttestationChecker(session, nonceFactory) {
  fun checkAppleAttestation(request: AppleRegistrationRequest): Either<KeycloakError, Unit> = either {
    val jwk = checkSignature(request).bind()
    val attestationObject = request.appleAttestationObject().mapLeft { it.toError() }.bind()
    val attestationStatement = attestationObject.appleAttestationStatement.mapLeft { it.toError() }.bind()
    val leafCertificate = attestationStatement.x5c[0]

    checkServerNonce(request).bind()

    checkCertificateNonce(request, leafCertificate, jwk).bind()

    checkCertificateChain(attestationStatement, leafCertificate).bind()

    checkAuthenticatorData(attestationObject.authenticatorData, leafCertificate).bind()
  }

  private fun checkAuthenticatorData(authenticatorData: AuthenticatorData<*>, leafCertificate: X509Certificate) = either {
    val attestedCredentialData =
        authenticatorData.attestedCredentialData ?: raise(keycloakError( "No attested credential data"))
    val keyId = leafCertificate.publicKey.toAppleKeyId()

    ensure(attestedCredentialData.aaguid == APPLE_APP_ATTEST_AAGUID) {
      keycloakError( "Invalid AAGUID »${attestedCredentialData.aaguid}«")
    }

    ensure(authenticatorData.signCount == 0L) {
      keycloakError( "Invalid counter »${authenticatorData.signCount}«")
    }

    ensure(attestedCredentialData.credentialId.contentEquals(keyId)) {
      keycloakError( "Invalid credentialId not matching public key id")
    }
  }

  private fun checkCertificateChain(attestationStatement: AppleAppAttestAttestationStatement, leafCertificate: X509Certificate) = either {
    val intermediateCertificate = attestationStatement.x5c[1]

    validateCertificateSignature(leafCertificate, intermediateCertificate.publicKey)
        .mapLeft { keycloakError( it) }
        .bind()

    val rootCertificate = appleTrustStore.findIssuerCertificate(intermediateCertificate)
      ?: raise(
          KeycloakError(
              INVALID_CLIENT_METADATA,
              "Root certificate not found: »${intermediateCertificate.issuerX500Principal}«",
              BAD_REQUEST
          )
      )

    validateCertificateChain(rootCertificate, attestationStatement.x5c)
        .mapLeft { keycloakError( it) }.bind()
  }

  private fun checkCertificateNonce(request: AppleRegistrationRequest, leafCertificate: X509Certificate, jwk: JWK) = either {
    val nonceFromCertificate = leafCertificate.extractAppleNonce()
      ?: raise(keycloakError( "Could not extract nonce data"))
    val clientDataHash = jwk.toClientHashData(request.nonce()).toHash()
    val rawAttestationObject = request.appleAttestationObject?.fromBase64()
      ?: raise(keycloakError( "Could not extract attestation statement"))
    val authData = rawAttestationObject.extractRawAuthenticationData().mapLeft { it.toError() }.bind()
    val nonceToHash = (authData + clientDataHash).toHash()

    ensure(nonceFromCertificate.contentEquals(nonceToHash)) {
      keycloakError( "Certificate nonce does not match")
    }
  }
}
