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
package de.gematik.zeta.zetaguard.keycloak.plugins.wellknown

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonPropertyDescription
import java.net.URI

/**
 * Created from https://github.com/gematik/zeta/blob/main/src/schemas/as-well-known.yaml using online conversion tool https://www.jsonschema2pojo.org/
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ZetaGuardWellKnownConfiguration(
    @field:JsonProperty("issuer") @field:JsonPropertyDescription("The URL of the issuer.") val issuer: URI,
    @field:JsonProperty("authorization_endpoint")
    @field:JsonPropertyDescription("The URL of the authorization endpoint.")
    val authorizationEndpoint: URI,
    @field:JsonProperty("token_endpoint") @field:JsonPropertyDescription("The URL of the token endpoint.") val tokenEndpoint: URI,
    // as-well-known.yaml v1.1.0
    @field:JsonProperty("pushed_authorization_request_endpoint")
    @field:JsonPropertyDescription("The URL of the pushed authorization request endpoint.")
    val pushedAuthorizationRequestEndpoint: URI,
    // as-well-known.yaml v1.1.0
    @field:JsonProperty("require_pushed_authorization_requests")
    @field:JsonPropertyDescription("Indicates whether the Authorization Server requires pushed authorization requests. In ZETA, this is always true.")
    val requirePushedAuthorizationRequests: Boolean,
    // A_29672
    @field:JsonProperty("redirection_endpoint")
    @field:JsonPropertyDescription("The URL of the redirection endpoint of the Authorization Server acting as OIDC Relying Party.")
    val redirectionEndpoint: URI,
    @field:JsonProperty("nonce_endpoint") @field:JsonPropertyDescription("The URL of the nonce endpoint.") val nonceEndpoint: URI,
    @field:JsonProperty("openid_providers_endpoint")
    @field:JsonPropertyDescription("The URL of the openid providers endpoint.")
    val openidProvidersEndpoint: URI,
    @field:JsonProperty("jwks_uri") @field:JsonPropertyDescription("The URL of the JSON Web Key Set.") val jwksUri: URI,
    @field:JsonProperty("scopes_supported")
    @field:JsonPropertyDescription("The scopes supported by the authorization server.")
    val scopesSupported: List<String>,
    @field:JsonProperty("registration_endpoint") @field:JsonPropertyDescription("The client registration endpoint.") val registrationEndpoint: URI,
    @field:JsonProperty("response_types_supported")
    @field:JsonPropertyDescription("The response types supported by the authorization server.")
    val responseTypesSupported: List<String>,
    @field:JsonProperty("response_modes_supported")
    @field:JsonPropertyDescription("The response modes supported by the authorization server.")
    val responseModesSupported: List<String>,
    @field:JsonProperty("grant_types_supported")
    @field:JsonPropertyDescription("The grant types supported by the authorization server.")
    val grantTypesSupported: List<String>,
    @field:JsonProperty("token_endpoint_auth_methods_supported")
    @field:JsonPropertyDescription("The token endpoint authentication methods supported.")
    val tokenEndpointAuthMethodsSupported: List<String>,
    @field:JsonProperty("token_endpoint_auth_signing_alg_values_supported")
    @field:JsonPropertyDescription("The signing algorithms supported at the token endpoint.")
    val tokenEndpointAuthSigningAlgValuesSupported: List<String>,
    // A_29996
    @field:JsonProperty("revocation_endpoint")
    @field:JsonPropertyDescription("The URL of the token revocation endpoint (RFC 7009).")
    val revocationEndpoint: URI,
    @field:JsonProperty("service_documentation") @field:JsonPropertyDescription("A URL to the service documentation.") val serviceDocumentation: URI,
    @field:JsonProperty("code_challenge_methods_supported")
    @field:JsonPropertyDescription("The code challenge methods supported for PKCE.")
    val codeChallengeMethodsSupported: List<String>,
    // A_29691
    @field:JsonProperty("api_versions_supported")
    @field:JsonPropertyDescription("The token-issuance contract versions supported by this Authorization Server.")
    val apiVersionsSupported: List<ApiVersion>,
) {
  // JSON deserialization
  @Suppress("unused")
  constructor() :
      this(
          issuer = URI.create(""),
          authorizationEndpoint = URI.create(""),
          tokenEndpoint = URI.create(""),
          pushedAuthorizationRequestEndpoint = URI.create(""),
          requirePushedAuthorizationRequests = true,
          redirectionEndpoint = URI.create(""),
          nonceEndpoint = URI.create(""),
          openidProvidersEndpoint = URI.create(""),
          jwksUri = URI.create(""),
          scopesSupported = listOf(),
          registrationEndpoint = URI.create(""),
          responseTypesSupported = listOf(),
          responseModesSupported = listOf(),
          grantTypesSupported = listOf(),
          tokenEndpointAuthMethodsSupported = listOf(),
          tokenEndpointAuthSigningAlgValuesSupported = listOf(),
          revocationEndpoint = URI.create(""),
          serviceDocumentation = URI.create(""),
          codeChallengeMethodsSupported = listOf(),
          apiVersionsSupported = listOf(),
      )
}

/**
 * Entry of `api_versions_supported`: a token-issuance contract version supported by this Authorization Server.
 */
// A_29691
@JsonInclude(JsonInclude.Include.NON_NULL)
data class ApiVersion(
    @field:JsonProperty("major_version")
    @field:JsonPropertyDescription("The major version number of the token-issuance contract.")
    val majorVersion: Int,
    @field:JsonProperty("version")
    @field:JsonPropertyDescription("The full, stable Semantic Versioning (SemVer) compliant string for this contract version.")
    val version: String,
    @field:JsonProperty("status") @field:JsonPropertyDescription("The release status of this contract version.") val status: String,
    @field:JsonProperty("documentation_uri")
    @field:JsonPropertyDescription("URL of the documentation specific to this contract version.")
    val documentationUri: URI? = null,
) {
  // JSON deserialization
  @Suppress("unused") constructor() : this(majorVersion = 0, version = "", status = "")
}
