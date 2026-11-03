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

import com.webauthn4j.data.attestation.authenticator.AAGUID
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.client_attestation.APPLE_APP_ATTEST_AAGUID_DEVELOPMENT
import de.gematik.zeta.zetaguard.keycloak.commons.APPLE_TRUSTSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.AppleAuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory.createAppleAuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory.createClientRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AppleRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.mockk.every
import io.mockk.mockk
import java.security.KeyPair

class AppleAttestationCheckerTest : AbstractAttestationCheckerTest() {
  private val appleTrustStore =
      KeystoreService(
          "APPLE",
          AppleAttestationCheckerTest::class.java.getResourceAsStream("/apple-certificates-server.p12")!!,
          APPLE_TRUSTSTORE_PASSWORD
      )

  private val checker = AppleAttestationChecker(session, nonceFactory, appleTrustStore)

  private fun appleRequest(
      leafKeyPair: KeyPair = generateKeyPair(),
      authenticatorData: AppleAuthenticatorData = createAppleAuthenticatorData(leafKeyPair.public)
  ) = createClientRegistrationRequest(
      PKIData(generateKeyPair()), nonce, leafKeyPair,
      attestationType = AttestationType.APPLE, appleAuthenticatorData = authenticatorData
  ) as AppleRegistrationRequest

  init {
    context("valid attestation") {
      test("development AAGUID is not accepted by default") {
        val leafKeyPair = generateKeyPair()
        val request = appleRequest(
            leafKeyPair,
            createAppleAuthenticatorData(leafKeyPair.public, aaguid = AAGUID(APPLE_APP_ATTEST_AAGUID_DEVELOPMENT.toByteArray()))
        )

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("Invalid AAGUID")
      }

      test("Default production AAGUID is accepted") {
        val request = appleRequest()

        checker.checkAppleAttestation(request).shouldBeRight()
      }
    }

    context("client data signature") {
      test("missing signature is rejected") {
        val request = appleRequest().apply { signedHashPukClientSig = null }

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("No client data signature")
      }

      test("signature by another key is rejected") {
        val request = appleRequest().apply { signedHashPukClientSig = appleRequest().signedHashPukClientSig }

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("Invalid client data signature")
      }
    }

    context("attestation object") {
      test("missing attestation object is rejected") {
        val request = appleRequest().apply { appleAttestationObject = null }

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("No valid Apple attestation object")
      }

      test("attestation object issued for another key is rejected (nonce mismatch)") {
        val request = appleRequest().apply { appleAttestationObject = appleRequest().appleAttestationObject }

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("Certificate nonce does not match")
      }

      test("unknown root certificate is rejected") {
        val emptyTrustStore = mockk<KeystoreService> { every { findIssuerCertificate(any()) } returns null }

        AppleAttestationChecker(session, nonceFactory, emptyTrustStore)
            .checkAppleAttestation(appleRequest())
            .shouldBeLeft()
            .shouldMatch("Root certificate not found")
      }
    }

    context("authenticator data") {
      test("missing attested credential data is rejected") {
        val leafKeyPair = generateKeyPair()
        val request = appleRequest(leafKeyPair, AuthenticatorData("vlgZtsDKrXBcPmQJ-sgPhsaaWFfofqpC3v-ZlDVH-G0".fromBase64(), 64.toByte(), 0))

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("No attested credential data")
      }

      test("counter other than 0 is rejected") {
        val leafKeyPair = generateKeyPair()
        val request = appleRequest(leafKeyPair, createAppleAuthenticatorData(leafKeyPair.public, signCount = 1))

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("Invalid counter »1«")
      }

      test("credentialId not matching the key id of the leaf certificate is rejected") {
        val leafKeyPair = generateKeyPair()
        val request = appleRequest(leafKeyPair, createAppleAuthenticatorData(leafKeyPair.public, credentialId = "jens".toByteArray()))

        checker.checkAppleAttestation(request).shouldBeLeft().shouldMatch("Invalid credentialId")
      }
    }
  }
}
