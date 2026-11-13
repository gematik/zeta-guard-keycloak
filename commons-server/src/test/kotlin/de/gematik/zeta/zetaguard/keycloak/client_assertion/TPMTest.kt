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

import de.gematik.zeta.zetaguard.keycloak.client_attestation.TPM_ATTEST_MAGIC
import de.gematik.zeta.zetaguard.keycloak.client_attestation.deserializeQuote
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldNotThrowAny
import io.kotest.matchers.shouldBe
import java.nio.ByteBuffer
import tss.tpm.TPMS_ATTEST
import tss.tpm.TPM_GENERATED

class TPMTest : ZetaGuardFunSpec() {
  init {
    val tpmAttestationKey = "yH-hHUAhTzX1H6WMhYBqehf1hqJVUr-flHPrKsqqpEIrRrwgmMwGF-vYOTN0v6Ej8uGnyoOeR92sgnD6cet1vQ=="
    val tpmQuote =
        "_1RDR4AYACIAC5AgE-j7_fsgTyVokI-7wf1v1bIRYBgbzcJQ6zU8YcTPACCrq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urqwAAAAABCx0BHWNGlsOY8YsBlRTWaepDsjsAAAABAAsDgQCAACAuqauRmNFjgAdADNLDvvHMdFuGS3YBGg4bxSGArGRS1A=="
    val tpmSignature = "vOLjjEzbr2EyBZfQb8PNHAHQlPrSd-PRaz-F4WWV_32Irh6AvMqHtVpAfECr-3pcEYxddXZ9b4XNZTxNq-c6Zw=="

    test("Data from client") {
      val publicKey = tpmAttestationKey.toPublicKey().shouldBeRight()
      val verifier = publicKey.createVerifierContext()
      val quoteBytes = tpmQuote.fromBase64()

      shouldNotThrowAny { verifier.verify(quoteBytes, tpmSignature.fromBase64()) } shouldBe true

      val buffer = ByteBuffer.wrap(quoteBytes)
      buffer.getInt() shouldBe TPM_ATTEST_MAGIC

      val quote = quoteBytes.deserializeQuote().shouldBeRight()
      quote.magic shouldBe TPM_GENERATED.VALUE
      quote.extraData.size shouldBe 32
      val dummyChallenge = 0xab.toByte()
      quote.extraData.forEach { it shouldBe dummyChallenge }

      // make sure our own parser is compatible with the unsafe library parser
      quote.toBytes() shouldBe TPMS_ATTEST.fromBytes(quoteBytes).toBytes()
    }

    test("Manipulated data cannot force memory exhaustion") {
      val quoteBytes = tpmQuote.fromBase64()
      // at this position, there is a four byte array length; force it to Integer.MAX_VALUE
      val i = 101
      quoteBytes[i] = 0x7F.toByte()
      quoteBytes[i + 1] = 0xFF.toByte()
      quoteBytes[i + 2] = 0xFF.toByte()
      quoteBytes[i + 3] = 0xFF.toByte()
      quoteBytes.deserializeQuote().shouldBeLeft()
    }

    test("Truncated quote is rejected") {
      val quoteBytes = tpmQuote.fromBase64()
      quoteBytes.copyOf(quoteBytes.size - 1).deserializeQuote().shouldBeLeft()
    }

    test("Quote with trailing data is rejected") {
      val quoteBytes = tpmQuote.fromBase64()
      quoteBytes.copyOf(quoteBytes.size + 1).deserializeQuote().shouldBeLeft()
    }
  }
}
