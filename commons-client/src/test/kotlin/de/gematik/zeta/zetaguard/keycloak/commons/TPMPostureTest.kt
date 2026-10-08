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

import de.gematik.zeta.zetaguard.keycloak.client_attestation.TPM_ATTEST_MAGIC
import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.client_attestation.deserializeQuote
import de.gematik.zeta.zetaguard.keycloak.client_attestation.validateQuoteSignature
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.publicKey
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.rootCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.TPMPostureHelper.subjectKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.SimpleSuccess
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toJWK
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.toThumbprint
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import org.junit.platform.commons.util.ReflectionUtils.tryToReadFieldValue
import org.keycloak.common.util.SecretGenerator
import tss.TpmEnum
import tss.tpm.TPMS_QUOTE_INFO

class TPMPostureTest : ZetaGuardFunSpec() {
  init {
    val keystoreServiceWithoutIntermediate: KeystoreService = mockk()

    beforeTest {
      every { keystoreServiceWithoutIntermediate.findIssuerCertificate(leafCertificate) } returns null
      every { keystoreServiceWithoutIntermediate.findIssuerCertificate(intermediateCertificate) } returns rootCertificate
    }

    test("Create and validate TPM posture") {
      val nonce = SecretGenerator.getInstance().randomBytes(16)
      val thumbprint = subjectKeyPair.toJWK().toThumbprint()
      val attestationChallenge = calculateAttestationChallenge(thumbprint, nonce).fromBase64()
      val posture = generateTpmPosture(attestationChallenge, subjectKeyPair, listOf(leafCertificate, intermediateCertificate))
      val tpmQuoteBytes = posture.tpmQuote.fromBase64()
      val tpmQuote = tpmQuoteBytes.deserializeQuote().shouldBeRight()
      val magic = tryToReadFieldValue(TpmEnum::class.java, "Value", tpmQuote.magic).get()

      magic shouldBe TPM_ATTEST_MAGIC
      val postureKey = posture.tpmAttestationKey.toPublicKey() shouldBeRight publicKey
      tpmQuote.extraData shouldBe attestationChallenge
      tpmQuote.attested.javaClass shouldBe TPMS_QUOTE_INFO::class.java

      tpmQuoteBytes.validateQuoteSignature(posture.tpmQuoteSignature.fromBase64(), postureKey) shouldBeRight SimpleSuccess

      val certificateChain = posture.tpmEkCertificateChain.map { it.toCertificate() }

      validateCertificateChain(keystoreServiceWithoutIntermediate, certificateChain).shouldBeRight()
    }
  }
}
