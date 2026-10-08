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

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownProviderFactory.Companion.DEFAULT_URI
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownProviderFactory.Companion.serviceDocumentationUri
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.net.URI

class ZetaGuardWellKnownConfigurationTest : FunSpec() {
  init {
    test("Serialization of ZetaGuardWellKnownConfiguration works") {
      val mapper = ObjectMapper()
      val uri = URI.create("http://localhost:8080/nonce")
      val parUri = URI.create("http://localhost:8080/par")
      val redirectionUri = URI.create("http://localhost:8080/broker/endpoint")
      val revocationUri = URI.create("http://localhost:8080/revoke")
      val config =
          ZetaGuardWellKnownConfiguration(
              issuer = URI.create("http://localhost:8080/issuer"),
              authorizationEndpoint = URI.create("http://localhost:8080"),
              tokenEndpoint = URI.create("http://localhost:8080/token"),
              pushedAuthorizationRequestEndpoint = parUri,
              requirePushedAuthorizationRequests = true,
              redirectionEndpoint = redirectionUri,
              nonceEndpoint = uri,
              openidProvidersEndpoint = URI.create("http://localhost:8080"),
              jwksUri = URI.create("http://localhost:8080"),
              scopesSupported = listOf("jens"),
              registrationEndpoint = URI.create("http://localhost:8080/client-registrations"),
              responseTypesSupported = listOf("jens"),
              responseModesSupported = listOf("jens"),
              grantTypesSupported = listOf("jens"),
              tokenEndpointAuthMethodsSupported = listOf("jens"),
              tokenEndpointAuthSigningAlgValuesSupported = listOf("jens"),
              revocationEndpoint = revocationUri,
              serviceDocumentation = URI.create("http://localhost:8080"),
              codeChallengeMethodsSupported = listOf("jens"),
              apiVersionsSupported = listOf(ApiVersion(majorVersion = 1, version = "1.0.0", status = "stable")),
          )

      val json = mapper.writeValueAsString(config)
      json shouldContain "\"nonce_endpoint\":\"$uri\""
      json shouldContain "\"pushed_authorization_request_endpoint\":\"$parUri\""
      json shouldContain "\"require_pushed_authorization_requests\":true"
      json shouldContain "\"redirection_endpoint\":\"$redirectionUri\""
      json shouldContain "\"revocation_endpoint\":\"$revocationUri\""
      json shouldContain "\"api_versions_supported\":[{\"major_version\":1,\"version\":\"1.0.0\",\"status\":\"stable\"}]"

      val deserialized = mapper.readValue(json, ZetaGuardWellKnownConfiguration::class.java)

      deserialized.nonceEndpoint shouldBe uri
      deserialized.pushedAuthorizationRequestEndpoint shouldBe parUri
      deserialized.requirePushedAuthorizationRequests shouldBe true
      deserialized.redirectionEndpoint shouldBe redirectionUri
      deserialized.revocationEndpoint shouldBe revocationUri
      deserialized.apiVersionsSupported shouldBe listOf(ApiVersion(majorVersion = 1, version = "1.0.0", status = "stable"))
    }

    test("URI parsing return default on error") {
      serviceDocumentationUri { null } shouldBe DEFAULT_URI
      serviceDocumentationUri { "http://localhost:8080" } shouldBe URI("http://localhost:8080")
      serviceDocumentationUri { "://localhost:8080" } shouldBe DEFAULT_URI
    }
  }
}
