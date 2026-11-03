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

import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidRootOfTrust
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidSecurityLevel
import de.gematik.zeta.zetaguard.keycloak.client_attestation.AndroidVerifiedBootState
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory.createAndroidKeyDescription
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory.createClientRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.GOOGLE_TRUSTSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AndroidRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.createSerialNumber
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toClientHashData
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.GoogleCertificateStatusService
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.mockk.every
import io.mockk.mockk
import java.math.BigInteger

class GoogleAttestationCheckerTest : AbstractAttestationCheckerTest() {
  private val stream = GoogleAttestationCheckerTest::class.java.getResourceAsStream("/status.json")!!
  private val googleCertificateStatusService = GoogleCertificateStatusService(stream)
  private val googleTrustStore =
      KeystoreService("GOOGLE", GoogleAttestationCheckerTest::class.java.getResourceAsStream("/google-certificates-server.p12")!!, GOOGLE_TRUSTSTORE_PASSWORD)
  private val checker = GoogleAttestationChecker(session, nonceFactory, googleTrustStore, googleCertificateStatusService)

  private fun androidRequest(
      pki: PKIData = PKIData(generateKeyPair()),
      keyDescription: AndroidKeyDescription = createAndroidKeyDescription(pki.jwk.toClientHashData(nonce).toHash()),
      serialNumber: BigInteger = createSerialNumber()
  ) = createClientRegistrationRequest(
      pki,
      nonce,
      attestationType = AttestationType.ANDROID,
      androidKeyDescription = keyDescription,
      leafSerialNumber = serialNumber
  ) as AndroidRegistrationRequest

  private fun androidRequest(keyDescription: (ByteArray) -> AndroidKeyDescription): AndroidRegistrationRequest {
    val pki = PKIData(generateKeyPair())

    return androidRequest(pki, keyDescription(pki.jwk.toClientHashData(nonce).toHash()))
  }

  init {
    context("valid attestation") {
      test("StrongBox attestation is accepted") {
        checker.checkAndroidAttestation(androidRequest()).shouldBeRight()
      }

      test("TEE attestation is accepted") {
        val request = androidRequest { createAndroidKeyDescription(it, securityLevel = AndroidSecurityLevel.TRUSTED_ENVIRONMENT) }

        checker.checkAndroidAttestation(request).shouldBeRight()
      }

      test("chain without root certificate is accepted") {
        val request = androidRequest().apply { androidKeyAttestationCertificateChain = androidKeyAttestationCertificateChain!!.dropLast(1) }

        checker.checkAndroidAttestation(request).shouldBeRight()
      }
    }

    context("nonce") {
      test("invalid nonce is rejected") {
        nonce = ByteArray(16)
        val request = androidRequest()

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid nonce value")
      }
    }

    context("client data signature") {
      test("missing signature is rejected") {
        val request = androidRequest().apply { signedHashPukClientSig = null }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("No client data signature")
      }

      test("signature by another key is rejected") {
        val request = androidRequest().apply { signedHashPukClientSig = androidRequest().signedHashPukClientSig }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid client data signature")
      }
    }

    context("certificate chain") {
      test("missing certificate chain is rejected") {
        val request = androidRequest().apply { androidKeyAttestationCertificateChain = null }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("No Android key attestation certificate chain found")
      }

      test("revoked certificate is rejected") {
        val request = androidRequest(serialNumber = "c8966fcb2fbb0d7a".toBigInteger(16))

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Revoked certificate")
      }

      test("chain consisting of leaf and root only is rejected") {
        val request = androidRequest().apply { androidKeyAttestationCertificateChain = androidKeyAttestationCertificateChain!!.drop(1) }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid Android key attestation certificate chain")
      }

      test("leaf certificate not signed by intermediate certificate is rejected") {
        val request = androidRequest().apply {
          val chain = androidKeyAttestationCertificateChain!!
          androidKeyAttestationCertificateChain = listOf(chain[1], chain[1], chain[2])
        }

        checker.checkAndroidAttestation(request).shouldBeLeft()
      }

      test("unknown root certificate is rejected") {
        val emptyTrustStore = mockk<KeystoreService> { every { findIssuerCertificate(any()) } returns null }

        GoogleAttestationChecker(session, nonceFactory, emptyTrustStore, googleCertificateStatusService)
            .checkAndroidAttestation(androidRequest())
            .shouldBeLeft()
            .shouldMatch("Root certificate not found")
      }

      test("certificate chain issued for another key is rejected (challenge mismatch)") {
        val request = androidRequest().apply { androidKeyAttestationCertificateChain = androidRequest().androidKeyAttestationCertificateChain }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Attestation challenge does not match")
      }
    }

    context("key description") {
      test("software attestation is rejected") {
        val request = androidRequest { createAndroidKeyDescription(it, securityLevel = AndroidSecurityLevel.SOFTWARE) }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid attestation security level »SOFTWARE«")
      }

      test("imported key is rejected") {
        val request = androidRequest { createAndroidKeyDescription(it, origin = 2) }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid key origin »2«")
      }

      test("missing root of trust is rejected") {
        val request = androidRequest { createAndroidKeyDescription(it, rootOfTrust = null) }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("No root of trust")
      }

      test("unlocked bootloader is rejected") {
        val request = androidRequest {
          createAndroidKeyDescription(it, rootOfTrust = AndroidRootOfTrust(ByteArray(32), false, AndroidVerifiedBootState.VERIFIED))
        }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Device bootloader is not locked")
      }

      test("unverified boot state is rejected") {
        val request = androidRequest {
          createAndroidKeyDescription(it, rootOfTrust = AndroidRootOfTrust(ByteArray(32), true, AndroidVerifiedBootState.UNVERIFIED))
        }

        checker.checkAndroidAttestation(request).shouldBeLeft().shouldMatch("Invalid verified boot state »UNVERIFIED«")
      }
    }
  }
}
