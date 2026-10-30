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
package de.gematik.zeta.zetaguard.keycloak.client_assertion

import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import de.gematik.zeta.zetaguard.keycloak.commons.server.toJWK
import de.gematik.zeta.zetaguard.keycloak.commons.server.toThumbprint
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import java.security.SecureRandom

val SECURE_RANDOM = SecureRandom()

class AttestationUtilTest : ZetaGuardFunSpec() {
  init {
    test("Generate attestation challenge") {
      val thumbprint = generateKeyPair().toJWK().toThumbprint()
      val nonceBytes = ByteArray(16).apply { SECURE_RANDOM.nextBytes(this) }
      val attestationChallenge = shouldNotThrowAny { calculateAttestationChallenge(thumbprint, nonceBytes) }

      attestationChallenge shouldBe toHash(thumbprint, nonceBytes).toBase64()
    }

    test("Hashing multiple byte arrays") {
      val thumbprint = generateKeyPair().toJWK().toThumbprint()
      val nonceBytes = ByteArray(16).apply { SECURE_RANDOM.nextBytes(this) }
      val attestationChallenge = shouldNotThrowAny { calculateAttestationChallenge(thumbprint, nonceBytes) }
      val bytes =
          ByteArray(thumbprint.size + nonceBytes.size).apply {
            thumbprint.copyInto(this, destinationOffset = 0)
            nonceBytes.copyInto(this, destinationOffset = thumbprint.size)
          }

      attestationChallenge shouldBe bytes.toHash().toBase64()
    }
  }
}
