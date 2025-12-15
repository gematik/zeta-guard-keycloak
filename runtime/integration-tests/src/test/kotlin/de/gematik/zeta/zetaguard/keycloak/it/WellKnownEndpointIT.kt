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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakResponse
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_FULL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.WELLKNOWN_BASE_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.WELLKNOWN_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownConfiguration
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.apache.http.client.methods.RequestBuilder.get

@Order(1)
class WellKnownEndpointIT : FunSpec() {
  init {
    test("Query well-known endpoint") {
      val keycloakWebClient = KeycloakWebClient()
      val wellknown = keycloakWebClient.getWellknown().shouldBeRight().reponseObject
      val nonceUri = keycloakWebClient.uriBuilder().createUri(NONCE_FULL_PATH, ZETA_REALM)

      wellknown.nonceEndpoint shouldBe nonceUri
      wellknown.serviceDocumentation.toString() shouldContain "https://gemspec.gematik.de/"
      wellknown.apiVersionsSupported[0].documentationUri.toString() shouldContain "https://gemspec.gematik.de/"

      wellknown.responseTypesSupported.shouldContainExactlyInAnyOrder("code", "token")
    }
  }
}

private fun KeycloakWebClient.getWellknown(): KeycloakResponse<ZetaGuardWellKnownConfiguration> {
  val request = get(uriBuilder().createUri("$WELLKNOWN_BASE_PATH/$WELLKNOWN_PROVIDER_ID", ZETA_REALM))

  return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<ZetaGuardWellKnownConfiguration>()
}
