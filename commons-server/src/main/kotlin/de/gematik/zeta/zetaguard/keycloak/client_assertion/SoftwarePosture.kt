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

private const val PUBLIC_KEY = "public_key"

private const val ATTESTATION_CHALLENGE = "attestation_challenge"

class SoftwarePosture
@ConstructorProperties(
    PROPERTY_PLATFORM_PRODUCT_ID,
    PROPERTY_PRODUCT_ID,
    PROPERTY_PRODUCT_VERSION,
    PROPERTY_OS,
    PROPERTY_OS_VERSION,
    PROPERTY_ARCHITECTURE,
    PUBLIC_KEY,
    ATTESTATION_CHALLENGE,
)
constructor(
    platformProductId: ProductId?,
    productId: String,
    productVersion: String,
    @field:JsonPropertyDescription("Operating system name") @field:JsonProperty(PROPERTY_OS) val os: String,
    @field:JsonPropertyDescription("Operating system version") @field:JsonProperty(PROPERTY_OS_VERSION) val osVersion: String,
    @field:JsonPropertyDescription("Hardware Architecture") @field:JsonProperty(PROPERTY_ARCHITECTURE) val arch: String,
    @field:JsonPropertyDescription("The public self-signed signing key (PEM or base64 DER encoded).")
    @field:JsonProperty(PUBLIC_KEY)
    val publicKey: String,
    @field:JsonPropertyDescription(
        "The attestation challenge of the client instance, used to verify the public client instance key and the nonce from AS."
    )
    @field:JsonProperty(ATTESTATION_CHALLENGE)
    val attestationChallenge: String,
) : Posture(platformProductId, productId, productVersion)
