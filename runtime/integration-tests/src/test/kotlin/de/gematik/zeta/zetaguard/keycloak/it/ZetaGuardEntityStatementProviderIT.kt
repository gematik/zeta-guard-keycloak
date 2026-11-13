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

import com.fasterxml.jackson.databind.JsonNode
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.ClientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.MediaTypes
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPublicKey
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kcHostname
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.withClue
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.nio.charset.StandardCharsets.UTF_8
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jws.JWSInput
import org.keycloak.protocol.oidc.utils.OIDCResponseType
import org.keycloak.util.JsonSerialization

/**
 * Tests the entity statement served at `/.well-known/openid-federation` (A_23034-02) including its
 * `redirect_uris` content (A_25656).
 */
class ZetaGuardEntityStatementProviderIT : ZetaGuardFunSpecIT() {
  init {
    test("A_23034-02: the entity statement is a JWS with typ=entity-statement+jwt, ES256 and a kid") {
      val header = entityStatement().header

      header.type shouldBe "entity-statement+jwt"
      header.rawAlgorithm shouldBe "ES256"
      header.keyId.shouldNotBeNull()
    }

    test("ANFTI2-1074: the entity statement is served as application/entity-statement+jwt, whatever the Accept header") {
      listOf(null, MediaTypes.ENTITY_STATEMENT_JWT, MediaTypes.JWT, "application/json", "*/*").forEach { accept ->
        withClue("Accept: $accept") {
          val response = keycloakWebClient.fetchEntityStatement(accept).shouldBeRight()

          response.responseHeaders shouldContain (CONTENT_TYPE to MediaTypes.ENTITY_STATEMENT_JWT)
          JWSInput(response.responseObject).header.type shouldBe "entity-statement+jwt"
        }
      }
    }

    test("A_23034-02: the signature verifies against the embedded jwks") {
      val statement = entityStatement()
      val signingKey = statement.body().federationKeys().single { it.keyId == statement.header.keyId }

      val verified =
          signingKey
              .toPublicKey()
              .createVerifierContext()
              .verify(statement.encodedSignatureInput.toByteArray(UTF_8), statement.signature)

      verified shouldBe true
    }

    test("A_23034-02: iss equals sub equals the realm URL and the statement has a validity window") {
      val body = entityStatement().body()

      body.path("iss").asText() shouldBe "$kcHostname/realms/$ZETA_REALM"
      body.path("sub").asText() shouldBe "$kcHostname/realms/$ZETA_REALM"
      body.path("exp").asLong() shouldBeGreaterThan body.path("iat").asLong()
    }

    test("A_23034-02: the federation jwks holds only sig keys and the RP metadata provides an enc key") {
      val body = entityStatement().body()

      body.federationKeys().map { it.publicKeyUse }.distinct() shouldBe listOf("sig")
      body.relyingPartyKeys().map { it.publicKeyUse } shouldContain "enc"
    }

    test("A_23034-02: the RP metadata carries the required protocol values") {
      val body = entityStatement().body()
      val relyingParty = body.relyingParty()

      relyingParty.path("response_types").texts() shouldBe listOf("code")
      relyingParty.path("grant_types").texts() shouldBe listOf("authorization_code")
      relyingParty.path("client_registration_types").texts() shouldBe listOf("automatic")
      relyingParty.path("require_pushed_authorization_requests").asBoolean() shouldBe true
      relyingParty.path("token_endpoint_auth_method").asText() shouldBe "self_signed_tls_client_auth"
      relyingParty.path("id_token_signed_response_alg").asText() shouldBe "ES256"
      relyingParty.path("id_token_encrypted_response_alg").asText() shouldBe "ECDH-ES"
      relyingParty.path("id_token_encrypted_response_enc").asText() shouldBe "A256GCM"
      relyingParty.path("scope").asText() shouldBe SEKIDP_DEFAULT_SCOPE
      body.path("authority_hints").texts() shouldBe listOf(FEDMASTER_URL)
    }

    test("A_27598: the RP metadata carries ti_features_supported with id_token_version_supported") {
      val relyingParty = entityStatement().body().relyingParty()

      val tiFeatures = relyingParty.path("ti_features_supported")
      tiFeatures.isMissingNode shouldBe false
      val versions = tiFeatures.path("id_token_version_supported").texts()
      versions shouldContain "1.0.0"
    }

    test("A_27598: the RP metadata carries client_name, organization_name, contacts, keywords and default_acr_values") {
      val relyingParty = entityStatement().body().relyingParty()

      relyingParty.path("client_name").asText() shouldBe "zeta-guard"
      relyingParty.path("organization_name").asText() shouldBe "zeta-guard"

      val contacts = relyingParty.path("contacts").texts()
      contacts.shouldNotBeEmpty()

      val keywords = relyingParty.path("keywords").texts()
      keywords shouldContainAll listOf("product_type:ZETA Guard", "product_type_version:1.0.0")

      relyingParty.path("default_acr_values").texts() shouldContain "gematik-ehealth-loa-high"
    }

    test("gemSpec_IDP_Sek Tab. 28: the metadata carries federation_entity with name and organization_name") {
      val federationEntity = entityStatement().body().path("metadata").path("federation_entity")

      federationEntity.path("name").asText() shouldBe "zeta-guard"
      federationEntity.path("organization_name").asText() shouldBe "zeta-guard"
    }

    test("A_25656: redirect_uris contains only redirect URIs of SekIDP clients") {
      val firstClientUris = listOf("https://first-sekidp-client.invalid/cb/app", "https://first-sekidp-client.invalid/cb/oidc")
      val secondClientUris = listOf("https://second-sekidp-client.invalid/cb/app", "https://second-sekidp-client.invalid/cb/oidc")

      registerSekIdpClient(firstClientUris)
      registerSekIdpClient(secondClientUris)

      val redirectUris = entityStatement().body().relyingParty().path("redirect_uris").texts()

      redirectUris shouldContainAll firstClientUris
      redirectUris shouldContainAll secondClientUris

      val sekIdpRedirectUris = sekIdpClientRedirectUris()

      redirectUris shouldContainExactlyInAnyOrder sekIdpRedirectUris
    }
  }

  // Deliberately not the query the endpoint uses: auth method from the client data, redirect URIs from the admin API.
  private fun sekIdpClientRedirectUris(): List<String> {
    val sekIdpClientIds = JpaEntityManagerFactory(Docker.dbhost, Docker.dbport, *entityClasses).use {
      it.createEntityManager()
          .createQuery("SELECT c.id FROM ZetaGuardClientData c WHERE c.clientAuthMethod = :authMethod", String::class.java)
          .setParameter("authMethod", ClientAuthMethod.SEK_IDP)
          .resultList
          .toSet()
    }

    return keycloakWebClient.withKeycloak(clientId = ADMIN_CLIENT) {
      realm(ZETA_REALM).clients().findAll()
          .filter { it.clientId in sekIdpClientIds }
          .flatMap { it.redirectUris.orEmpty() }
          .distinct()
    }
  }

  private fun registerSekIdpClient(redirectUris: List<String>) {
    val key = ClientAssertionTokenGenerator()
    val request = ClientRegistrationRequestFactory.createClientRegistrationRequest(
        key.keys,
        null,
        redirectUris = redirectUris,
        grantTypes = SEKIDP_VALID_GRANT_TYPES,
        responseTypes = listOf(OIDCResponseType.CODE),
        attestationType = AttestationType.APPLE,
    )
    keycloakWebClient
        .registerClientOIDC(clientRegistrationRequest = request)
        .shouldBeRight()
  }

  private fun entityStatement(): JWSInput {
    val token = keycloakWebClient.fetchEntityStatement().shouldBeRight().responseObject

    return JWSInput(token)
  }
}

// Must match the test entry in runtime/federation-master.json and defaultScope of the IdP instance.
private const val FEDMASTER_URL = "http://gsi-fedmaster:8083"
private const val SEKIDP_DEFAULT_SCOPE = "urn:telematik:display_name urn:telematik:versicherter urn:telematik:geburtsdatum openid"

private fun JWSInput.body(): JsonNode = JsonSerialization.mapper.readTree(content)

private fun JsonNode.keys(): List<JWK> = path("keys").map { JsonSerialization.mapper.treeToValue(it, JWK::class.java) }

private fun JsonNode.federationKeys(): List<JWK> = path("jwks").keys()

private fun JsonNode.relyingParty(): JsonNode = path("metadata").path("openid_relying_party")

private fun JsonNode.relyingPartyKeys(): List<JWK> = relyingParty().path("jwks").keys()

private fun JsonNode.texts(): List<String> = map { it.asText() }
