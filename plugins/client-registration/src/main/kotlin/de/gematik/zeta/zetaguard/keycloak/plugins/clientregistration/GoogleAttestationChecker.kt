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
import de.gematik.zeta.zetaguard.keycloak.client_attestation.ANDROID_KEY_ORIGIN_GENERATED
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidSecurityLevel
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidVerifiedBootState
import de.gematik.zeta.zetaguard.keycloak.client_attestation.extractAndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.androidCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.nonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.GoogleCertificateStatusService
import de.gematik.zeta.zetaguard.keycloak.plugins.nonce.NonceFactory
import java.security.cert.X509Certificate
import org.keycloak.jose.jwk.JWK
import org.keycloak.models.KeycloakSession

/**
 * @see [https://developer.android.com/privacy-and-security/security-key-attestation#verifying]
 */
class GoogleAttestationChecker(
    session: KeycloakSession, nonceFactory: NonceFactory,
    private val googleTrustStore: KeystoreService,
    private val googleCertificateStatusService: GoogleCertificateStatusService
) : AbstractAttestationChecker(session, nonceFactory) {
  fun checkAndroidAttestation(request: AndroidRegistrationRequest): Either<KeycloakError, Unit> = either {
    val jwk = checkSignature(request).bind()
    val certificateChain = request.androidCertificateChain().mapLeft { it.toError() }.bind()

    checkServerNonce(request).bind()

    checkCertificateChain(certificateChain).bind()

    val keyDescription = certificateChain[0].extractAndroidKeyDescription().mapLeft { it.toError() }.bind()

    checkAttestationChallenge(keyDescription, jwk, request.nonce()).bind()

    checkKeyDescription(keyDescription).bind()
  }

  /**
   * The leaf certificate is only checked for its signature, since its validity period is not reliable on all devices. The (optional) root
   * certificate sent by the client is ignored, the trust anchor is taken from the trust store instead.
   */
  private fun checkCertificateChain(certificateChain: List<X509Certificate>) = either {
    certificateChain.forEach {
      ensure(googleCertificateStatusService.isValid(it)) {
        keycloakError("Revoked certificate »${it.serialNumber.toString(16)}«")
      }
    }

    val certificates = certificateChain.dropLastWhile { it.isRoot() }

    ensure(certificates.size >= 2) { keycloakError("Invalid Android key attestation certificate chain") }

    val leafCertificate = certificates[0]
    val intermediateCertificate = certificates[1]

    validateCertificateSignature(leafCertificate, intermediateCertificate.publicKey)
        .mapLeft { keycloakError(it) }
        .bind()

    val rootCertificate = googleTrustStore.findIssuerCertificate(certificates.last())
      ?: raise(
          keycloakError("Root certificate not found: »${certificates.last().issuerX500Principal}«")
      )

    validateCertificateChain(rootCertificate, certificates.drop(1))
        .mapLeft { keycloakError(it) }.bind()
  }

  private fun checkAttestationChallenge(keyDescription: AndroidKeyDescription, jwk: JWK, nonce: ByteArray?) = either {
    val clientDataHash = jwk.toClientHashData(nonce).toHash()

    ensure(keyDescription.attestationChallenge.contentEquals(clientDataHash)) {
      keycloakError("Attestation challenge does not match")
    }
  }

  private fun checkKeyDescription(keyDescription: AndroidKeyDescription) = either {
    ensure(keyDescription.attestationSecurityLevel != AndroidSecurityLevel.SOFTWARE) {
      keycloakError("Invalid attestation security level »${keyDescription.attestationSecurityLevel}«")
    }

    ensure(keyDescription.keyMintSecurityLevel != AndroidSecurityLevel.SOFTWARE) {
      keycloakError("Invalid KeyMint security level »${keyDescription.keyMintSecurityLevel}«")
    }

    val hardwareEnforced = keyDescription.hardwareEnforced

    ensure(hardwareEnforced.origin == ANDROID_KEY_ORIGIN_GENERATED) {
      keycloakError("Invalid key origin »${hardwareEnforced.origin}«")
    }

    val rootOfTrust = hardwareEnforced.rootOfTrust ?: raise(keycloakError("No root of trust"))

    ensure(rootOfTrust.deviceLocked) { keycloakError("Device bootloader is not locked") }

    ensure(rootOfTrust.verifiedBootState == AndroidVerifiedBootState.VERIFIED) {
      keycloakError("Invalid verified boot state »${rootOfTrust.verifiedBootState}«")
    }
  }
}
