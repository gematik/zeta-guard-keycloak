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

import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_USER
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator.buildCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_PENDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_VALID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_ATTESTATION_STATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.jwsTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.smcbTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.SMCBTokenHelper.subjectKeyPair
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.nondeterministic.eventually
import io.kotest.assertions.nondeterministic.eventuallyConfig
import io.kotest.assertions.withClue
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import kotlin.time.Duration.Companion.seconds
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_TOKEN
import org.keycloak.OAuthErrorException.UNAUTHORIZED_CLIENT
import org.keycloak.models.jpa.entities.ClientAttributeEntity
import org.keycloak.models.jpa.entities.ClientEntity
import org.keycloak.models.jpa.entities.ClientScopeAttributeEntity
import org.keycloak.models.jpa.entities.ClientScopeEntity
import org.keycloak.models.jpa.entities.ProtocolMapperEntity
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_INITIAL_ACCESS_TOKEN
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_REGISTRATION_ACCESS_TOKEN

@Order(1)
class ClientRegistrationIT : FunSpec() {
  init {
    val keycloakWebClient = KeycloakWebClient()
    var nonce = ""
    var smbcToken = ""
    var jws = ""
    var oidcClientResponse = OIDCClientRepresentation()
    val baseUri = keycloakWebClient.uriBuilder().build().toString()
    val audiences = if (keycloakWebClient.path.isNotEmpty() && !baseUri.endsWith("/")) listOf("$baseUri/") else listOf(baseUri)

    beforeTest {
      oidcClientResponse = keycloakWebClient.createClientOIDC(jwsTokenGenerator.keys.jwks).shouldBeRight().reponseObject
      jws = jwsTokenGenerator.generateClientAssertion(oidcClientResponse)
      nonce = keycloakWebClient.getNonce().shouldBeRight().reponseObject
      // Other/new PKI
      smbcToken =
          smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = audiences,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(leafCertificate),
          )
    }

    test("Token exchange using OIDC, DPoP and client_assertion") {
      val accessToken = oidcClientResponse.registrationAccessToken.toAccessToken()

      accessToken.type shouldBe TYPE_REGISTRATION_ACCESS_TOKEN
      accessToken.issuer shouldContain ZETA_REALM

      keycloakWebClient.checkAttestationState(oidcClientResponse.clientId, ATTESTATION_STATE_PENDING)

      val accessTokenResponse =
          keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws)

      accessTokenResponse.token.shouldNotBeNull()
      accessTokenResponse.refreshToken.shouldNotBeNull()

      keycloakWebClient.checkAttestationState(oidcClientResponse.clientId, ATTESTATION_STATE_VALID)
    }

    test("Client registration expiration") {
      lookupClient(oidcClientResponse.clientId) shouldBe true

      // Poll until the client is expired instead of fixed sleep to avoid flakiness
      withClue("Client still present after 10 seconds (id=${oidcClientResponse.clientId})") {
        val config = eventuallyConfig {
          duration = 10.seconds
          interval = 1.seconds
          initialDelay = 1.seconds
        }

        eventually(config) { lookupClient(oidcClientResponse.clientId) shouldBe false }
      }
    }

    test("Certificate signature validation fails") {
      val certificate =
          buildCertificate(
              subjectName = leafCertificate.subjectX500Principal.toString(),
              subjectKeyPair = subjectKeyPair,
              issuerName = leafCertificate.issuerX500Principal.toString(),
              issuerKeyPair = subjectKeyPair,
              isCA = false,
          )

      smbcToken =
          smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = audiences,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(certificate),
          )

      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "certificate does not verify"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Unknown certificate issuer") {
      smbcToken =
          smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = audiences,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(smcbTokenGenerator.certificate),
          )

      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "issuer not found"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails, because of unknown public key signature of client assertion JWT") {
      val jws = SMCBTokenGenerator().generateClientAssertion(oidcClientResponse) // Gnerates (unknowwn) new keys and certificates

      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Unable to load public key"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails, because of wrong signature of client assertion JWT") {
      val originalJWS = jws
      val tokenParts = originalJWS.split('.').also { it.size shouldBe 3 }
      val corruptedSignature = tokenParts[2].fromBase64().apply { this[42] = 123 }.toBase64()

      keycloakWebClient.testExchangeToken(
          subjectToken = smbcToken,
          clientId = oidcClientResponse.clientId,
          clientAssertion = tokenParts[0] + '.' + tokenParts[1] + '.' + corruptedSignature,
      ) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldContain "signed JWT failed"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails for wrong issuer in client_assertion") {
      val invalidJWS =
          jwsTokenGenerator.generateSMCBToken(
              issuer = "wrongIssuer",
              subject = oidcClientResponse.clientId,
              audiences = audiences,
              issuedFor = oidcClientResponse.clientId,
          )

      /**
       * Issuer must match subject, see [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       *
       * Actually, there is a bug in Keycloak that causes a NPE subsequently in [org.keycloak.authentication.ClientAuthenticationFlow.processResult],
       * because the "status" field is not set by the client validator. So the failure test succeeds, but for the wrong reason. This may be get fixed
       * in later versions of KC.
       */
      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe UNAUTHORIZED_CLIENT
        it.errorDescription shouldContain "Unexpected error"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails because of wrong subject in client_assertion") {
      val invalidJWS =
          jwsTokenGenerator.generateSMCBToken(
              issuer = oidcClientResponse.clientId,
              subject = "jens",
              audiences = listOf(oidcClientResponse.clientId),
              issuedFor = oidcClientResponse.clientId,
          )

      /**
       * client_id must match subject in JWS token See [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       */
      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "client_id parameter does not match sub claim"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails because of wrong audience in JWS in client_assertion") {
      /**
       * audience must match token audience (http://.../zeta-guard), see
       * [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       */
      val invalidJWS =
          jwsTokenGenerator.generateSMCBToken(
              issuer = oidcClientResponse.clientId,
              subject = oidcClientResponse.clientId,
              audiences = listOf("jens"),
              issuedFor = oidcClientResponse.clientId,
          )
      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Invalid token audience"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Register client via initial access token using Keycloak method") {
      val initialAccessToken = keycloakWebClient.createInitialAccessToken()
      val newClientId = KeycloakModelUtils.generateId()
      val keycloakClientResponse = keycloakWebClient.createClientKeycloak(initialAccessToken, newClientId).shouldBeRight().reponseObject
      val registrationAccessToken = keycloakClientResponse.registrationAccessToken.toAccessToken()
      val clientId = keycloakClientResponse.clientId
      val audiences2 = registrationAccessToken.audience.toList()
      val jws = jwsTokenGenerator.generateClientAssertion(clientId, audiences2)

      smbcToken =
          smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = audiences,
              issuer = keycloakClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(leafCertificate),
          )

      registrationAccessToken.type shouldBe TYPE_REGISTRATION_ACCESS_TOKEN
      registrationAccessToken.issuer shouldContain ZETA_REALM

      keycloakWebClient.testExchangeToken(subjectToken = smbcToken, clientAssertion = jws, clientId = newClientId)
    }
  }

  private fun lookupClient(clientId: String): Boolean {
    val entityClasses =
        arrayOf(
            ClientEntity::class.java,
            ClientAttributeEntity::class.java,
            ProtocolMapperEntity::class.java,
            ClientScopeEntity::class.java,
            ClientScopeAttributeEntity::class.java,
        )

    return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
      it.createEntityManager()
          .createQuery("SELECT realmId FROM ClientEntity WHERE clientId = :client_id")
          .setParameter("client_id", clientId)
          .resultList
          .isNotEmpty()
    }
  }

  private fun KeycloakWebClient.checkAttestationState(clientId: String, expectedState: String) {
    withKeycloak(clientId = ADMIN_CLIENT) {
      val client = realm(ZETA_REALM).clients().get(clientId)
      client.toRepresentation().attributes[ATTRIBUTE_ATTESTATION_STATE] shouldBe expectedState
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}

private fun KeycloakWebClient.createInitialAccessToken(): String {
  val accessTokenResponse =
      login(realm = ADMIN_REALM, client = ADMIN_CLIENT, user = ADMIN_USER, password = ADMIN_PASSWORD).shouldBeRight().reponseObject

  val initialAccessTokenResponse = createInitialAccessToken(accessTokenResponse.token)
  val initialAccessToken = initialAccessTokenResponse.shouldBeRight().reponseObject.token
  val accessToken = initialAccessToken.toAccessToken()

  accessToken.type shouldBe TYPE_INITIAL_ACCESS_TOKEN
  accessToken.issuer shouldContain ZETA_REALM

  logout(ZETA_REALM)
  return initialAccessToken
}
