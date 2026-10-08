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

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import java.beans.ConstructorProperties

private const val TPM_QUOTE_SIGNATURE = "tpm_quote_signature"
private const val TPM_QUOTE = "tpm_quote"
private const val TPM_ATTESTATION_KEY = "tpm_attestation_key"
private const val TPM_EVENT_LOG = "tpm_event_log"
private const val TPM_EK_CERTIFICATE_CHAIN = "tpm_ek_certificate_chain"

class TPMPosture
@ConstructorProperties(
    PROPERTY_PLATFORM_PRODUCT_ID,
    PROPERTY_PRODUCT_ID,
    PROPERTY_PRODUCT_VERSION,
    PROPERTY_OS,
    PROPERTY_OS_VERSION,
    PROPERTY_ARCHITECTURE,
    TPM_ATTESTATION_KEY,
    TPM_QUOTE,
    TPM_QUOTE_SIGNATURE,
    TPM_EVENT_LOG,
    TPM_EK_CERTIFICATE_CHAIN,
)
constructor(
    platformProductId: ProductId?,
    productId: String,
    productVersion: String,
    @field:JsonPropertyDescription("Operating system name") @field:JsonProperty(PROPERTY_OS) val os: String,
    @field:JsonPropertyDescription("Operating system version") @field:JsonProperty(PROPERTY_OS_VERSION) val osVersion: String,
    @field:JsonPropertyDescription("Hardware Architecture") @field:JsonProperty(PROPERTY_ARCHITECTURE) val arch: String,
    @field:JsonPropertyDescription("The public key of the TPM-resident attestation key (PEM or base64 DER encoded).")
    @field:JsonProperty(TPM_ATTESTATION_KEY)
    val tpmAttestationKey: String,
    @field:JsonPropertyDescription("The TPM quote of the client instance") @field:JsonProperty(TPM_QUOTE) val tpmQuote: String,
    @field:JsonPropertyDescription("The signature of the TPM quote created by the TPM-resident attestation key")
    @field:JsonProperty(TPM_QUOTE_SIGNATURE)
    val tpmQuoteSignature: String,
    @field:JsonPropertyDescription("The TPM event log of the client instance") @field:JsonProperty(TPM_EVENT_LOG) val tpmEventLog: String,
    @field:JsonProperty(TPM_EK_CERTIFICATE_CHAIN)
    @field:JsonPropertyDescription("The endorsement key certificate chain from the TPM manufacturer (PEM or base64 DER encoded).")
    val tpmEkCertificateChain: List<String>,
) : Posture(platformProductId, productId, productVersion)
