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
package de.gematik.zeta.zetaguard.keycloak.it

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory
import com.networknt.schema.JsonSchemaFactory
import com.networknt.schema.SpecVersion
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakResponse
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_FULL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.WELLKNOWN_BASE_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.WELLKNOWN_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ApiVersion
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownConfiguration
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.apache.http.client.methods.RequestBuilder.get

class WellKnownEndpointIT : FunSpec() {
  val keycloakWebClient = KeycloakWebClient.instance()

  init {
    afterSpec { keycloakWebClient.close() }

    test("Query well-known endpoint") {
      val wellknown = keycloakWebClient.getWellknown().shouldBeRight().reponseObject
      val nonceUri = keycloakWebClient.uriBuilder().createUri(NONCE_FULL_PATH, ZETA_REALM)

      wellknown.nonceEndpoint shouldBe nonceUri
      wellknown.serviceDocumentation.toString() shouldContain "https://gemspec.gematik.de/"

      wellknown.responseTypesSupported.shouldContainExactlyInAnyOrder("code", "token")
    }

    test("Well-known announces PAR, redirection, revocation and api versions") {
      val wellknown = keycloakWebClient.getWellknown().shouldBeRight().reponseObject

      // A_29660
      wellknown.pushedAuthorizationRequestEndpoint.toString() shouldContain "/realms/$ZETA_REALM/protocol/openid-connect/ext/par/request"
      wellknown.requirePushedAuthorizationRequests shouldBe true
      // A_29672
      wellknown.redirectionEndpoint.toString() shouldContain "/realms/$ZETA_REALM/broker/$SEKIDP_IDENTITY_PROVIDER_ID/endpoint"
      // A_29996
      wellknown.revocationEndpoint.toString() shouldContain "/realms/$ZETA_REALM/protocol/openid-connect/revoke"
      // A_29691
      wellknown.apiVersionsSupported shouldBe listOf(ApiVersion(majorVersion = 1, version = "1.0.0", status = "stable"))
    }

    test("Well-known response validates against as-well-known.yaml schema") {
      val json = keycloakWebClient.getWellknownJson().shouldBeRight().reponseObject

      val schemaNode = ObjectMapper(YAMLFactory()).readTree(javaClass.getResource("/as-well-known.yaml"))
      val schema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7).getSchema(schemaNode)

      schema.validate(ObjectMapper().readTree(json)).shouldBeEmpty()
    }
  }
}

private fun KeycloakWebClient.getWellknown(): KeycloakResponse<ZetaGuardWellKnownConfiguration> {
  val request = get(uriBuilder().createUri("$WELLKNOWN_BASE_PATH/$WELLKNOWN_PROVIDER_ID", ZETA_REALM))

  return httpClient().execute(request.build()).mapJSONResponse<ZetaGuardWellKnownConfiguration>()
}

private fun KeycloakWebClient.getWellknownJson(): KeycloakResponse<String> {
  val request = get(uriBuilder().createUri("$WELLKNOWN_BASE_PATH/$WELLKNOWN_PROVIDER_ID", ZETA_REALM))

  return httpClient().execute(request.build()).mapStringResponse()
}
