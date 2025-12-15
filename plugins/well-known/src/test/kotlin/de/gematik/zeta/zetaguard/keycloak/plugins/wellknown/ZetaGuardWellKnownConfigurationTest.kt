/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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
      val config =
          ZetaGuardWellKnownConfiguration(
              URI.create("http://localhost:8080/issuer"),
              URI.create("http://localhost:8080"),
              URI.create("http://localhost:8080/token"),
              uri,
              URI.create("http://localhost:8080"),
              URI.create("http://localhost:8080"),
              listOf("jens"),
              listOf("jens"),
              listOf("jens"),
              listOf("jens"),
              listOf("jens"),
              listOf("jens"),
              URI.create("http://localhost:8080"),
              listOf("jens"),
              listOf("jens"),
              listOf(ApiVersionsSupported()),
          )

      val json = mapper.writeValueAsString(config)
      json shouldContain "\"nonce_endpoint\":\"$uri\""
      json shouldContain "\"status\":\"alpha\""

      val (
          issuer,
          authorizationEndpoint,
          tokenEndpoint,
          nonceEndpoint,
          openidProvidersEndpoint,
          jwksUri,
          scopesSupported,
          responseTypesSupported,
          responseModesSupported,
          grantTypesSupported,
          tokenEndpointAuthMethodsSupported,
          tokenEndpointAuthSigningAlgValuesSupported,
          serviceDocumentation,
          uiLocalesSupported,
          codeChallengeMethodsSupported,
          api) =
          mapper.readValue(json, ZetaGuardWellKnownConfiguration::class.java)

      nonceEndpoint shouldBe uri
      api.size shouldBe 1
      api[0].status shouldBe Status.alpha
    }

    test("URI parsing return default on error") {
      serviceDocumentationUri { null } shouldBe DEFAULT_URI
      serviceDocumentationUri { "http://localhost:8080" } shouldBe URI("http://localhost:8080")
      serviceDocumentationUri { "://localhost:8080" } shouldBe DEFAULT_URI
    }
  }
}
