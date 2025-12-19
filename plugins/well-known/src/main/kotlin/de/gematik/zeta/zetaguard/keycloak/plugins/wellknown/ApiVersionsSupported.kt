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
package de.gematik.zeta.zetaguard.keycloak.plugins.wellknown

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import java.net.URI

/**
 * Created from https://github.com/gematik/zeta/blob/main/src/schemas/as-well-known.yaml using online conversion tool https://www.jsonschema2pojo.org/
 */
data class ApiVersionsSupported(
    @field:JsonProperty("major_version") @field:JsonPropertyDescription("The major version number of the API.") val majorVersion: Int = 1,
    @field:JsonProperty("version")
    @field:JsonPropertyDescription("The full, stable Semantic Versioning (SemVer) compliant string for this API version.")
    val version: String = "1.0.0",
    @field:JsonProperty("status") @field:JsonPropertyDescription("The release status of this API version.") val status: Status = Status.alpha,
    @field:JsonProperty("documentation_uri")
    @field:JsonPropertyDescription("URL of the documentation specific to this API version.")
    val documentationUri: URI = URI("https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0"),
)

/** The release status of this API version. */
@Suppress("EnumEntryName", "unused")
enum class Status {
  stable,
  beta,
  alpha,
  deprecated,
  retired,
}
