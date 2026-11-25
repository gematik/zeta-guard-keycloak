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

package de.gematik.zeta.zetaguard.keycloak.client_attestation

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.commons.server.SimpleSuccess
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import java.security.PublicKey
import tss.TpmBuffer
import tss.tpm.TPMS_ATTEST
import tss.tpm.TPMS_CLOCK_INFO
import tss.tpm.TPMS_PCR_SELECTION
import tss.tpm.TPMS_QUOTE_INFO
import tss.tpm.TPM_GENERATED
import tss.tpm.TPM_ST
import tss.tpm.TPM_ST.ATTEST_QUOTE

const val TPM_ATTEST_MAGIC = 0xFF544347.toInt()
const val SIGNATURE_VALIDATION_FAILED = "Signature validation failed for TPM quote"
const val TPM_DESERIALIZATION_FAILED = "Could not read TPM quote"

// TPML_PCR_SELECTION.count must not exceed HASH_COUNT (one entry per hash algorithm), see TPM 2.0 Part 2
private const val MAX_PCR_SELECTIONS = 16

fun ByteArray.deserializeQuote() = either {
  Either.catch {
    // NOTE: This is an inlined version of TPMS_ATTEST.fromBytes() with safer array size check
    val buf = TpmBuffer(this@deserializeQuote)
    val magic = TPM_GENERATED.fromTpm(buf)
    require(magic == TPM_GENERATED.VALUE)
    val type = TPM_ST.fromTpm(buf)
    require(type == ATTEST_QUOTE)

    val qualifiedSigner = buf.readSizedByteBuf()
    val extraData = buf.readSizedByteBuf()
    val clockInfo = TPMS_CLOCK_INFO.fromTpm(buf)
    val firmwareVersion = buf.readInt64()

    val pcrSelect = buf.readPcrSelections()
    val pcrDigest = buf.readSizedByteBuf()
    require(buf.isOk && buf.curPos() == buf.size()) { "Malformed or trailing data in TPM quote" }
    val attested = TPMS_QUOTE_INFO(pcrSelect, pcrDigest)

    TPMS_ATTEST(magic, qualifiedSigner, extraData, clockInfo, firmwareVersion, attested)
  }
      .mapLeft {
        logger.error(TPM_DESERIALIZATION_FAILED, it)
        TPM_DESERIALIZATION_FAILED
      }
      .bind()
}

private fun TpmBuffer.readPcrSelections(): Array<TPMS_PCR_SELECTION> {
  val numElems = readInt()
  require(isOk && numElems in 0..MAX_PCR_SELECTIONS) { "Invalid number of PCR selections »$numElems«" }
  return Array(numElems) { TPMS_PCR_SELECTION.fromTpm(this) }
}

fun ByteArray.validateQuoteSignature(signature: ByteArray, publicKey: PublicKey) = either {
  val result =
      Either.catch { publicKey.createVerifierContext().verify(this@validateQuoteSignature, signature) }
          .mapLeft {
            logger.error(SIGNATURE_VALIDATION_FAILED, it)
            SIGNATURE_VALIDATION_FAILED
          }
          .bind()

  ensure(result) { SIGNATURE_VALIDATION_FAILED }

  SimpleSuccess
}
