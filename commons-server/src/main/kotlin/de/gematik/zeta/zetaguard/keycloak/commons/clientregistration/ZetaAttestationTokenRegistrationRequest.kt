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

private const val PROPERTY_ZETA_ATTESTATION_TOKEN = "zeta_attestation_token"
private const val PROPERTY_ATTESTATION_POP = "attestation_pop"

/**
 * ZETA Attestation Token (Fast-Path): re-uses a previously issued ZETA Guard Attestation Token instead of re-running the
 * platform-specific hardware attestation.
 *
 * https://github.com/gematik/zeta/blob/feature/zeta-stufe-2/src/schemas/dcr-request.yaml
 */
class ZetaAttestationTokenRegistrationRequest : ZetaGuardOIDCClientRequestRepresentation(AttestationType.ZETA_ATTESTATION_TOKEN) {
  @field:JsonPropertyDescription(
      "Signiertes JWT, ausgestellt vom ZETA Guard nach erfolgreicher Hardware-Attestierung. Enthält attestation_type (tpm | apple | android), puk_ak_sig (cnf.jwk) und verifizierte Plattform-Claims."
  )
  @field:JsonProperty(PROPERTY_ZETA_ATTESTATION_TOKEN)
  var zetaAttestationToken: String? = null

  @field:JsonPropertyDescription(
      "Frischer Besitznachweis des Attestation Keys (prk_ak_sig), bindet den (ggf. neuen) Client Instance Key an den bereits attestierten Attestation Key. Das Format bestimmt der AuthS anhand des attestation_type-Claims im zeta_attestation_token."
  )
  @field:JsonProperty(PROPERTY_ATTESTATION_POP)
  var attestationPop: String? = null
}
