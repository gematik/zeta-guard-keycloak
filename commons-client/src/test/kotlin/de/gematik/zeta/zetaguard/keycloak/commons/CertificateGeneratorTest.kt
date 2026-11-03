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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.extractAppleNonce
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import io.kotest.matchers.shouldBe
import java.security.KeyPair
import java.security.cert.X509Certificate

class CertificateGeneratorTest : ZetaGuardFunSpec() {
  init {
    test("Test apple nonce extension") {
      val rootKeyPair: KeyPair = generateKeyPair()
      val appleNonce = "nonce".toByteArray()
      val certificate: X509Certificate = CertificateGenerator(
          subjectName = APPLE_LEAF_DN,
          subjectKeyPair = rootKeyPair,
          issuerName = APPLE_ROOT_DN,
          issuerKeyPair = rootKeyPair,
          isCA = false,
          isRootCA = false,
          createAdmissionExtension = false,
          appleNonce = appleNonce
      ).buildCertificate()

      certificate.extractAppleNonce()?.contentEquals(appleNonce) shouldBe true
    }
  }
}

