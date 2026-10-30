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
import tss.tpm.TPMS_ATTEST

const val TPM_ATTEST_MAGIC = 0xFF544347.toInt()
const val SIGNATURE_VALIDATION_FAILED = "Signature validation failed for TPM quote"
const val TPM_DESERIALIZATION_FAILED = "Could not read TPM quote"

fun ByteArray.deserializeQuote() = either {
  Either.catch { TPMS_ATTEST.fromBytes(this@deserializeQuote) }
      .mapLeft {
        logger.error(TPM_DESERIALIZATION_FAILED, it)
        TPM_DESERIALIZATION_FAILED
      }
      .bind()
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
