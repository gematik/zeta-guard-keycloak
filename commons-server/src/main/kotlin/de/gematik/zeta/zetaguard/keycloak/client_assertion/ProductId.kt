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

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonValue
import java.beans.ConstructorProperties

const val PROPERTY_PLATFORM_DISCRIMINATOR = "platform"

// Android
const val PROPERTY_PACKAGE_NAME = "package_name"
const val PROPERTY_SHA_256_CERT_FINGERPRINTS = "sha256_cert_fingerprints"
const val PROPERTY_NAMESPACE = "namespace"

// Apple
const val PROPERTY_PLATFORM_TYPE = "platform_type"
const val PROPERTY_APP_BUNDLE_IDS = "app_bundle_ids"

// Linux
const val PROPERTY_PACKAGING_TYPE = "packaging_type"
const val PROPERTY_APPLICATION_ID = "application_id"

// Windows
const val PROPERTY_STORE_ID = "store_id"
const val PROPERTY_PACKAGE_FAMILY_NAME = "package_family_name"

@Suppress("unused")
enum class Platform {
  ANDROID,
  APPLE,
  LINUX,
  WINDOWS;

  @JsonValue //
  val value = name.lowercase()
}

@JsonIgnoreProperties(ignoreUnknown = true)
@JsonTypeInfo(use = JsonTypeInfo.Id.NAME, include = JsonTypeInfo.As.PROPERTY, property = PROPERTY_PLATFORM_DISCRIMINATOR, visible = true)
@JsonSubTypes(
    value =
        [
            JsonSubTypes.Type(value = AndroidProductId::class, name = "android"),
            JsonSubTypes.Type(value = AppleProductId::class, name = "apple"),
            JsonSubTypes.Type(value = LinuxProductId::class, name = "linux"),
            JsonSubTypes.Type(value = WindowsProductId::class, name = "windows"),
        ]
)
sealed class ProductId(
    @field:JsonProperty(PROPERTY_PLATFORM_DISCRIMINATOR) // Holds discriminator value
    @field:JsonIgnore // But is not written to JSON (would be duplicate)
    val productPlatform: Platform
)

data class AndroidProductId
@ConstructorProperties(PROPERTY_PACKAGE_NAME, PROPERTY_SHA_256_CERT_FINGERPRINTS)
constructor(
    @field:JsonProperty(PROPERTY_PACKAGE_NAME) val packageName: String,
    @field:JsonProperty(PROPERTY_SHA_256_CERT_FINGERPRINTS) val sha256CertFingerprints: List<String>,
) : ProductId(Platform.ANDROID) {
  @field:JsonProperty(PROPERTY_NAMESPACE) val namespace: String = "android_app"
}

data class AppleProductId
@ConstructorProperties(PROPERTY_PLATFORM_TYPE, PROPERTY_APP_BUNDLE_IDS)
constructor(
    @field:JsonProperty(PROPERTY_PLATFORM_TYPE) val platformType: String, //
    @field:JsonProperty(PROPERTY_APP_BUNDLE_IDS) val appBundleIds: List<String>,
) : ProductId(Platform.APPLE)

data class LinuxProductId
@ConstructorProperties(PROPERTY_PACKAGING_TYPE, PROPERTY_APPLICATION_ID)
constructor(
    @field:JsonProperty(PROPERTY_PACKAGING_TYPE) val packagingType: String, //
    @field:JsonProperty(PROPERTY_APPLICATION_ID) val applicationId: String,
) : ProductId(Platform.LINUX)

data class WindowsProductId
@ConstructorProperties(PROPERTY_STORE_ID, PROPERTY_PACKAGE_FAMILY_NAME)
constructor(
    @field:JsonProperty(PROPERTY_STORE_ID) val storeId: String, //
    @field:JsonProperty(PROPERTY_PACKAGE_FAMILY_NAME) val packageFamilyName: String,
) : ProductId(Platform.WINDOWS)
