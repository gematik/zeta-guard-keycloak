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
import com.fasterxml.jackson.annotation.JsonValue

const val PROPERTY_PRODUCT_ID = "product_id"
const val PROPERTY_PRODUCT_VERSION = "product_version"
const val PROPERTY_OS = "os"
const val PROPERTY_OS_VERSION = "os_version"
const val PROPERTY_ARCHITECTURE = "arch"

const val PROPERTY_PLATFORM_PRODUCT_ID = "platform_product_id"

abstract class Posture(
    @field:JsonPropertyDescription("The product identifier") @field:JsonProperty(PROPERTY_PLATFORM_PRODUCT_ID) val platformProductId: ProductId?,
    @field:JsonPropertyDescription("The gematik product identifier") @field:JsonProperty(PROPERTY_PRODUCT_ID) val productId: String,
    @field:JsonPropertyDescription("The product version") @field:JsonProperty(PROPERTY_PRODUCT_VERSION) val productVersion: String,
) {
  override fun equals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is Posture) return false

    return (platformProductId == other.platformProductId) && (productId == other.productId) && (productVersion == other.productVersion)
  }

  override fun hashCode() = platformProductId.hashCode() + productId.hashCode() + productVersion.hashCode()
}

@Suppress("unused")
enum class PostureType {
  ANDROID,
  APPLE,
  TPM,
  SOFTWARE;

  @JsonValue //
  val value = name.lowercase()
}
