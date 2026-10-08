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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.client_assertion.LinuxProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import de.gematik.zeta.zetaguard.keycloak.commons.server.createSignerContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDER
import de.gematik.zeta.zetaguard.keycloak.commons.server.toHash
import java.security.KeyPair
import java.security.cert.X509Certificate
import tss.tpm.TPMS_ATTEST
import tss.tpm.TPMS_CLOCK_INFO
import tss.tpm.TPMS_PCR_SELECTION
import tss.tpm.TPMS_QUOTE_INFO
import tss.tpm.TPM_ALG_ID
import tss.tpm.TPM_GENERATED

fun generatePCRS(): Map<Int, ByteArray> =
    mapOf(
        0 to "BIOS_v1.2.3".toByteArray().toHash(),
        2 to "OptionROMs".toByteArray().toHash(),
        4 to "Bootloader".toByteArray().toHash(),
        7 to "SecureBootEnabled".toByteArray().toHash(),
    )

fun computePcrDigest(pcrSelection: IntArray, pcrs: Map<Int, ByteArray>): ByteArray {
  val byteArrays = pcrSelection.map { pcrs[it]!! }.toTypedArray()

  return toHash(*byteArrays)
}

fun generateTpmQuote(attestationChallenge: ByteArray): TPMS_ATTEST {
  val pcrSelection = intArrayOf(0, 2, 4, 7)
  val pcrs = generatePCRS()
  val pcrDigest = computePcrDigest(pcrSelection, pcrs)

  return TPMS_ATTEST(
      TPM_GENERATED.VALUE,
      "signature".toByteArray(),
      attestationChallenge,
      TPMS_CLOCK_INFO(System.currentTimeMillis(), 0, 0, 0),
      0x00010002,
      TPMS_QUOTE_INFO(arrayOf(TPMS_PCR_SELECTION(TPM_ALG_ID.SHA256, pcrSelection)), pcrDigest),
  )
}

fun generateTpmPosture(attestationChallenge: ByteArray, keyPair: KeyPair, certificateChain: List<X509Certificate>): TPMPosture {
  val quote = generateTpmQuote(attestationChallenge).toBytes()
  val signer = keyPair.createSignerContext()
  val signature = signer.sign(quote)

  return TPMPosture(
      LinuxProductId("packaging", "app-id"),
      PRODUCT_ID,
      PRODUCT_VERSION,
      "Linux",
      "6.4",
      "aarch64",
      keyPair.public.toDER(),
      quote.toBase64(),
      signature.toBase64(),
      "events",
      certificateChain.map { it.toDER() },
  )
}
