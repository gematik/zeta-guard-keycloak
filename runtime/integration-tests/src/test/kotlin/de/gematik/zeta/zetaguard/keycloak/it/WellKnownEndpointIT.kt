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
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJsonNode
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kcHostname
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ApiVersion
import de.gematik.zeta.zetaguard.keycloak.plugins.wellknown.ZetaGuardWellKnownConfiguration
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

class WellKnownEndpointIT : ZetaGuardFunSpecIT() {
  init {
    val json = keycloakWebClient.fetchWellKnownJson().shouldBeRight().responseObject

    test("Query well-known endpoint") {
      val wellknown = json.toObject<ZetaGuardWellKnownConfiguration>()

      wellknown.nonceEndpoint.toString() shouldBe "$kcHostname/realms/$ZETA_REALM/$NONCE_PROVIDER_ID"
      wellknown.serviceDocumentation.toString() shouldContain "https://gemspec.gematik.de/"

      wellknown.responseTypesSupported.shouldContainExactlyInAnyOrder("code", "token")
    }

    test("Well-known announces PAR, redirection, revocation and api versions") {
      val wellknown = json.toObject<ZetaGuardWellKnownConfiguration>()

      // A_29660
      wellknown.pushedAuthorizationRequestEndpoint.toString() shouldContain "/realms/$ZETA_REALM/protocol/openid-connect/ext/par/request"
      wellknown.requirePushedAuthorizationRequests shouldBe true
      // A_29672
      wellknown.redirectionEndpoint.toString() shouldContain "/realms/$ZETA_REALM/broker/$SEKIDP_IDENTITY_PROVIDER_ID/endpoint"
      // A_29996
      wellknown.revocationEndpoint.toString() shouldContain "/realms/$ZETA_REALM/protocol/openid-connect/revoke"
      // A_29691
      wellknown.apiVersionsSupported shouldBe listOf(
          ApiVersion(majorVersion = 1, version = "1.0.0", status = "stable"),
          ApiVersion(majorVersion = 2, version = "2.0.0", status = "stable")
      )
    }

    test("Well-known response validates against as-well-known.yaml schema") {
      val schemaNode = ObjectMapper(YAMLFactory()).readTree(javaClass.getResourceAsStream("/as-well-known.yaml"))
      val schema = JsonSchemaFactory.getInstance(SpecVersion.VersionFlag.V7).getSchema(schemaNode)

      schema.validate(json.toJsonNode()).shouldBeEmpty()
    }
  }
}
