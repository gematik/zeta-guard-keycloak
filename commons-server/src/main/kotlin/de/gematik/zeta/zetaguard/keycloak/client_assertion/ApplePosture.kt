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
import org.keycloak.jose.jwk.JWK.X5C

private const val PROPERTY_SYSTEM_VERSION = "system_version"
private const val PROPERTY_SYSTEM_NAME = "system_name"
private const val PROPERTY_DEVICE_MODEL = "device_model"
private const val PROPERTY_KEY_ID = "key_id"
private const val PROPERTY_ATTESTATION_FORMAT = "fmt"
private const val PROPERTY_ATTESTATION_STATEMENT = "attStmt"
private const val PROPERTY_AUTH_DATA = "authData"
private const val PROPERTY_SIGNATURE = "signature"
private const val PROPERTY_ASSERTION_AUTHENTICATOR_DATA = "assertionAuthenticatorData"
private const val PROPERTY_CLIENT_DATA_JSON = "client_data_json"

/**
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.9.3.3
 */
class ApplePosture
@ConstructorProperties(
    PROPERTY_PLATFORM_PRODUCT_ID,
    PROPERTY_PRODUCT_ID,
    PROPERTY_PRODUCT_VERSION,
    PROPERTY_SYSTEM_VERSION,
    PROPERTY_SYSTEM_NAME,
    PROPERTY_DEVICE_MODEL,
    PROPERTY_KEY_ID,
    PROPERTY_ATTESTATION_FORMAT,
    PROPERTY_ATTESTATION_STATEMENT,
    PROPERTY_AUTH_DATA,
    PROPERTY_SIGNATURE,
    PROPERTY_ASSERTION_AUTHENTICATOR_DATA,
    PROPERTY_CLIENT_DATA_JSON
)
constructor(
    platformProductId: AppleProductId,
    productId: String,
    productVersion: String,
    @field:JsonPropertyDescription("Operating system version, e.g., 10.15.7")
    @field:JsonProperty(PROPERTY_SYSTEM_VERSION)
    val systemVersion: String,
    @field:JsonPropertyDescription("The name of the operating system running on the device.")
    @field:JsonProperty(PROPERTY_SYSTEM_NAME)
    val systemName: String,
    @field:JsonPropertyDescription("The model of the device, e.g., \"iPhone6,2\"")
    @field:JsonProperty(PROPERTY_DEVICE_MODEL)
    val deviceModel: String,
    @field:JsonPropertyDescription("The key identifier associated with the cryptographic key on the device (base64 encoded).")
    @field:JsonProperty(PROPERTY_KEY_ID)
    val keyId: String,
    @field:JsonPropertyDescription("The format of the attestation statement. For Apple App Attest, this is 'apple-appattest'.")
    @field:JsonProperty(PROPERTY_ATTESTATION_FORMAT)
    val fmt: String? = null,
    @field:JsonPropertyDescription("The attestation statement containing the actual attestation data.")
    @field:JsonProperty(PROPERTY_ATTESTATION_STATEMENT)
    val attStmt: ApplePostureAttestationStatement,
    @field:JsonPropertyDescription("Structured authenticator data from the initial attestation.")
    @field:JsonProperty(PROPERTY_AUTH_DATA)
    val authData: AppleAuthData,
    @field:JsonPropertyDescription("The cryptographic signature created by the private key on the device.")
    @field:JsonProperty(PROPERTY_SIGNATURE)
    val signature: String? = null,
    @field:JsonPropertyDescription("Simplified authenticator data for subsequent assertions.")
    @field:JsonProperty(PROPERTY_ASSERTION_AUTHENTICATOR_DATA)
    val assertionAuthenticatorData: AppleAssertionAuthenticatorData,
    @field:JsonPropertyDescription("A JSON string containing the request data to be signed, including a server-provided challenge.")
    @field:JsonProperty(PROPERTY_CLIENT_DATA_JSON)
    val clientDataJson: String? = null
) : Posture(platformProductId, productId, productVersion)

data class ApplePostureAttestationStatement
@ConstructorProperties(X5C, "receipt")
constructor(
    @field:JsonProperty(X5C)
    @field:JsonPropertyDescription("A chain of X.509 certificates, starting with the credential certificate.")
    val x5c: List<String>,
    @field:JsonProperty("receipt")
    @field:JsonPropertyDescription("An Apple-specific receipt for device risk assessment.")
    val receipt: String,
)

data class AppleAuthData
@ConstructorProperties("rpidHash", "flags", "counter", "aaguid", "credentialId")
constructor(
    @field:JsonProperty("rpidHash")
    @field:JsonPropertyDescription("SHA256 hash of the Relying Party ID (App ID).")
    val rpidHash: String,
    @field:JsonProperty("flags")
    @field:JsonPropertyDescription("A byte of flags indicating the authenticator's state.")
    val flags: String,
    @field:JsonProperty("counter")
    @field:JsonPropertyDescription("Signature counter, which is 0 during initial attestation.")
    val counter: Long,
    @field:JsonProperty("aaguid")
    @field:JsonPropertyDescription("Authenticator Attestation Globally Unique Identifier, indicating the environment (dev/prod).")
    val aaguid: String,
    @field:JsonProperty("credentialId") @field:JsonPropertyDescription("Hash of the public key of the attested key pair.")
    val credentialId: String,
)

data class AppleAssertionAuthenticatorData
@ConstructorProperties("rpidHash", "counter")
constructor(
    @field:JsonProperty("rpidHash")
    @field:JsonPropertyDescription("SHA256 hash of the Relying Party ID (App ID).")
    val rpidHash: String,
    @field:JsonProperty("counter")
    @field:JsonPropertyDescription("Signature counter, incremented for each assertion to prevent replay attacks.")
    val counter: Long,
)
