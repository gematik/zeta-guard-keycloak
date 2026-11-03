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

import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory.createClientRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.SoftwareRegistrationRequest
import de.gematik.zeta.zetaguard.keycloak.commons.server.CapecAttackMechanics.AUTHENTICATION_BYPASS
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.PKIData
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.reportAttack
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.mockk.verify

class SoftwareAttestationCheckerTest : AbstractAttestationCheckerTest() {
  private val checker = SoftwareAttestationChecker(session, nonceFactory)

  private fun softwareRequest(pki: PKIData = PKIData(generateKeyPair()), nonce: ByteArray? = this.nonce) =
      createClientRegistrationRequest(pki, nonce, attestationType = AttestationType.SOFTWARE) as SoftwareRegistrationRequest

  init {
    context("valid attestation") {
      test("request signed with the registered key and a server nonce is accepted") {
        checker.checkSoftwareAttestation(softwareRequest()).shouldBeRight()
      }
    }

    context("nonce") {
      test("unknown nonce is rejected and reported as attack") {
        nonce = ByteArray(16)

        checker.checkSoftwareAttestation(softwareRequest()).shouldBeLeft().shouldMatch("Invalid nonce value")

        verify { session.reportAttack(any<KeycloakError>(), AUTHENTICATION_BYPASS, "127.0.0.1") }
      }

      test("nonce can only be used once") {
        checker.checkSoftwareAttestation(softwareRequest()).shouldBeRight()
        checker.checkSoftwareAttestation(softwareRequest()).shouldBeLeft().shouldMatch("Invalid nonce value")
      }
    }

    context("client data signature") {
      test("missing signature is rejected") {
        val request = softwareRequest().apply { signedHashPukClientSig = null }

        checker.checkSoftwareAttestation(request).shouldBeLeft().shouldMatch("No client data signature")
      }

      test("signature by another key is rejected") {
        val request = softwareRequest().apply { signedHashPukClientSig = softwareRequest().signedHashPukClientSig }

        checker.checkSoftwareAttestation(request).shouldBeLeft().shouldMatch("Invalid client data signature")
      }

      test("signature over another nonce is rejected") {
        val request = softwareRequest().apply { signedHashPukClientSig = softwareRequest(nonce = ByteArray(16)).signedHashPukClientSig }

        checker.checkSoftwareAttestation(request).shouldBeLeft().shouldMatch("Invalid client data signature")
      }

      test("missing JWKS is rejected") {
        val request = softwareRequest().apply { jwks = null }

        checker.checkSoftwareAttestation(request).shouldBeLeft().shouldMatch("Invalid JWK")
      }
    }
  }
}
