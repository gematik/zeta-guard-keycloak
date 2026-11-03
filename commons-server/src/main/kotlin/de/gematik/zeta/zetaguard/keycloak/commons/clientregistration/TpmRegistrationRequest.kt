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
package de.gematik.zeta.zetaguard.keycloak.commons.clientregistration

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription

private const val PROPERTY_PUK_EK_ENC = "puk_ek_enc"
private const val PROPERTY_C_EK_ENC = "c_ek_enc"
private const val PROPERTY_PUK_AK_SIG = "puk_ak_sig"

/**
 * TPM Hardware Attestation (Windows / Linux).
 *
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 */
class TpmRegistrationRequest : ZetaGuardOIDCClientRequestRepresentation(AttestationType.TPM) {
  @field:JsonPropertyDescription(
      "Öffentlicher Endorsement Key (EK) des TPM als Base64-kodierte TPM2B_PUBLIC Struktur. Wird zur MakeCredential-Operation verwendet."
  )
  @field:JsonProperty(PROPERTY_PUK_EK_ENC)
  var pukEkEnc: String? = null

  @field:JsonPropertyDescription("Zertifikat des Endorsement Key (EK) des TPM im DER Format Base64-kodiert.")
  @field:JsonProperty(PROPERTY_C_EK_ENC)
  var cEkEnc: String? = null

  @field:JsonPropertyDescription(
      "Öffentlicher Attestation Key (AK) des TPM (Base64-kodierte TPM2B_PUBLIC-Bytes). Wird vom AuthS zur Verifikation der TPM-Quote und von signed_hash_puk_client_sig verwendet."
  )
  @field:JsonProperty(PROPERTY_PUK_AK_SIG)
  var pukAkSig: String? = null
}
