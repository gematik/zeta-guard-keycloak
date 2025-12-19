/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.commons.client_assertion

import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonValue
import java.beans.ConstructorProperties

const val FIELD_CLIENT_ID = "client_id"

/**
 * JSON classes for Client assertion
 *
 * The Client Statement is used in the Client Assertion JWT with the ZETA Guard AuthServer. It contains information about the client instance.
 *
 * @see [https://github.com/gematik/zeta/blob/main/src/schemas/client-instance.yaml]
 */
data class ZetaGuardClientInstanceData
@ConstructorProperties("name", FIELD_CLIENT_ID, "manufacturer_id", "manufacturer_name", "owner_mail", "registration_timestamp", "platform_product_id")
constructor(
    @field:JsonProperty("name") val name: String,
    @field:JsonProperty(FIELD_CLIENT_ID) val clientId: String,
    @field:JsonProperty("manufacturer_id") val manufacturerId: String,
    @field:JsonProperty("manufacturer_name") val manufacturerName: String,
    @field:JsonProperty("owner_mail") val ownerMail: String,
    @field:JsonProperty("registration_timestamp") val registrationTimestamp: Long,
    @field:JsonProperty("platform_product_id") val platformProductId: ZetaPlatformProductId,
)

@Suppress("unused")
enum class ZetaProductPlatform {
  ANDROID,
  APPLE,
  LINUX,
  WINDOWS;

  @JsonValue //
  val value = name.lowercase()
}

const val DISCRIMINATOR = "platform"

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = DISCRIMINATOR, visible = true)
@JsonSubTypes(
    value =
        [
            JsonSubTypes.Type(value = AndroidZetaPlatformProductId::class, name = "android"),
            JsonSubTypes.Type(value = AppleZetaPlatformProductId::class, name = "apple"),
            JsonSubTypes.Type(value = LinuxZetaPlatformProductId::class, name = "linux"),
            JsonSubTypes.Type(value = WindowsZetaPlatformProductId::class, name = "windows"),
        ]
)
sealed class ZetaPlatformProductId(@field:JsonProperty(DISCRIMINATOR) val productPlatform: ZetaProductPlatform? = null)

data class AndroidZetaPlatformProductId
@ConstructorProperties("package_name", "sha256_cert_fingerprints")
constructor(
    @field:JsonProperty("package_name") val packageName: String,
    @field:JsonProperty("sha256_cert_fingerprints") val sha256CertFingerprints: List<String>,
) : ZetaPlatformProductId() {
  @field:JsonProperty("namespace") val namespace: String = "android_app"
}

data class AppleZetaPlatformProductId
@ConstructorProperties("platform_type", "app_bundle_ids")
constructor(@field:JsonProperty("platform_type") val platformType: String, @field:JsonProperty("app_bundle_ids") val appBundleIds: List<String>) :
    ZetaPlatformProductId()

data class LinuxZetaPlatformProductId
@ConstructorProperties("packaging_type", "application_id")
constructor(@field:JsonProperty("packaging_type") val packagingType: String, @field:JsonProperty("application_id") val applicationId: String) :
    ZetaPlatformProductId()

data class WindowsZetaPlatformProductId
@ConstructorProperties("store_id", "package_family_name")
constructor(@field:JsonProperty("store_id") val storeId: String, @field:JsonProperty("package_family_name") val packageFamilyName: String) :
    ZetaPlatformProductId()
