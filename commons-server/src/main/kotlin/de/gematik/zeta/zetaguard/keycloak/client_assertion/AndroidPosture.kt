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

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import java.beans.ConstructorProperties

const val PROPERTY_BUILD = "build"
const val PROPERTY_RO = "ro"
const val PROPERTY_PACKAGE_MANAGER = "packageManager"
const val PROPERTY_KEYGUARD_MANAGER = "keyguardManager"
const val PROPERTY_BIOMETRIC_MANAGER = "biometricManager"
const val PROPERTY_DEVICE_POLICY_MANAGER = "devicePolicyManager"
const val PROPERTY_KEY_ATTESTATION_CERTIFICATE_CHAIN = "key_attestation_certificate_chain"

class AndroidPosture
@ConstructorProperties(
    PROPERTY_PLATFORM_PRODUCT_ID,
    PROPERTY_PRODUCT_ID,
    PROPERTY_PRODUCT_VERSION,
    PROPERTY_BUILD,
    PROPERTY_RO,
    PROPERTY_PACKAGE_MANAGER,
    PROPERTY_KEYGUARD_MANAGER,
    PROPERTY_BIOMETRIC_MANAGER,
    PROPERTY_DEVICE_POLICY_MANAGER,
    PROPERTY_KEY_ATTESTATION_CERTIFICATE_CHAIN,
)
constructor(
    platformProductId: AndroidProductId,
    productId: String,
    productVersion: String,
    @field:JsonPropertyDescription("Android build information, see https://developer.android.com/reference/android/os/Build")
    @field:JsonProperty(PROPERTY_BUILD)
    val build: Build,
    @field:JsonProperty(PROPERTY_RO) val ro: Ro,
    @field:JsonProperty(PROPERTY_PACKAGE_MANAGER) val packageManager: PackageManager,
    @field:JsonProperty(PROPERTY_KEYGUARD_MANAGER) val keyguardManager: KeyguardManager,
    @field:JsonProperty(PROPERTY_BIOMETRIC_MANAGER) val biometricManager: BiometricManager,
    @field:JsonProperty(PROPERTY_DEVICE_POLICY_MANAGER) val devicePolicyManager: DevicePolicyManager,
    @field:JsonPropertyDescription("The certificate chain from the Android Key Attestation")
    @field:JsonProperty(PROPERTY_KEY_ATTESTATION_CERTIFICATE_CHAIN)
    val keyAttestationCertificateChain: List<String>,
) : Posture(platformProductId, productId, productVersion)

data class Build
@ConstructorProperties("version", "manufacturer", "product", "model", "board")
constructor(
    @field:JsonProperty("version") val version: Version,
    @field:JsonProperty("manufacturer") val manufacturer: String,
    @field:JsonProperty("product") var product: String,
    @field:JsonProperty("model") val model: String,
    @field:JsonProperty("board") val board: String,
)

data class Version
@ConstructorProperties("sdk_init", "security_patch")
constructor(@field:JsonProperty("sdk_init") val sdkInit: Long, @field:JsonProperty("security_patch") val securityPatch: String)

data class Crypto @ConstructorProperties("state") constructor(@field:JsonProperty("state") val state: Boolean)

data class Product @ConstructorProperties("first_api_level") constructor(@field:JsonProperty("first_api_level") val firstApiLevel: Long)

data class Ro
@ConstructorProperties("crypto", "product")
constructor(@field:JsonProperty("crypto") val crypto: Crypto, @field:JsonProperty("product") val product: Product)

data class BiometricManager
@ConstructorProperties("deviceCredential", "biometricStrong")
constructor(
    @field:JsonProperty("deviceCredential") val deviceCredential: Boolean,
    @field:JsonProperty("biometricStrong") val biometricStrong: Boolean,
)

data class DevicePolicyManager
@ConstructorProperties("passwordComplexity")
constructor(@field:JsonProperty("passwordComplexity") val passwordComplexity: Long)

@JsonInclude(JsonInclude.Include.NON_NULL)
data class KeyguardManager @ConstructorProperties("isDeviceSecure") constructor(@field:JsonProperty("isDeviceSecure") var isDeviceSecure: Boolean)

data class PackageManager
@ConstructorProperties("feature_verified_boot", "mainline_patch_level")
constructor(
    @field:JsonProperty("feature_verified_boot") val featureVerifiedBoot: Boolean,
    @field:JsonProperty("mainline_patch_level") val mainlinePatchLevel: String,
)
