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

import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.ClientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory
import de.gematik.zeta.zetaguard.keycloak.commons.DN_GEMATIK
import de.gematik.zeta.zetaguard.keycloak.commons.DN_PRAXIS
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_ZETA_TEST
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ClientRegistrationState
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.ZetaGuardOIDCClientResponseRepresentation
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REALM_CLIENT_JOB_DISABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.OIDC_CLIENT_REGISTRATION_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.nondeterministic.eventually
import io.kotest.assertions.nondeterministic.eventuallyConfig
import io.kotest.assertions.withClue
import io.kotest.matchers.date.shouldBeAfter
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.LocalDateTime
import kotlin.time.Duration.Companion.seconds
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpHeaders.AUTHORIZATION
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.HttpStatus.SC_FORBIDDEN
import org.apache.http.HttpStatus.SC_METHOD_NOT_ALLOWED
import org.apache.http.HttpStatus.SC_UNAUTHORIZED
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.entity.ContentType.APPLICATION_JSON
import org.apache.http.entity.StringEntity
import org.apache.http.util.EntityUtils
import org.keycloak.admin.client.resource.BearerAuthFilter.AUTH_HEADER_PREFIX
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_TOKEN
import org.keycloak.models.jpa.entities.ClientAttributeEntity
import org.keycloak.models.jpa.entities.ClientEntity
import org.keycloak.models.jpa.entities.ClientScopeAttributeEntity
import org.keycloak.models.jpa.entities.ClientScopeEntity
import org.keycloak.models.jpa.entities.ProtocolMapperEntity
import org.keycloak.protocol.oidc.utils.OIDCResponseType
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_REGISTRATION_ACCESS_TOKEN

val entityClasses =
    arrayOf(
        ZetaGuardUserData::class.java,
        ZetaGuardClientData::class.java,
        ClientEntity::class.java,
        ClientAttributeEntity::class.java,
        ProtocolMapperEntity::class.java,
        ClientScopeEntity::class.java,
        ClientScopeAttributeEntity::class.java,
    )

class ClientRegistrationIT : ZetaGuardFunSpecIT() {
  init {
    var nonce = ""
    var smbcToken = ""
    var jws = ""
    var oidcClientResponse = ZetaGuardOIDCClientResponseRepresentation()

    beforeTest {
      val request = ClientRegistrationRequestFactory.createClientRegistrationRequest(clientAssertionTokenGenerator.keys, null)

      oidcClientResponse = keycloakWebClient.registerClientOIDC(clientRegistrationRequest = request).shouldBeRight().responseObject
      nonce = createNonce()
      jws = clientAssertionTokenGenerator.generateClientAssertion(oidcClientResponse, nonce)
      // Other/new PKI
      smbcToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              subject = smcb.telematikId,
              audiences = smcbTokenAudience,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(smcb.leafCertificate),
          )
    }

    test("Token exchange using OIDC, DPoP and client_assertion") {
      val now = currentTime().minusSeconds(1) // Due to truncation
      val accessToken = oidcClientResponse.registrationAccessToken.toAccessToken()

      accessToken.type shouldBe TYPE_REGISTRATION_ACCESS_TOKEN
      accessToken.issuer shouldContain ZETA_REALM

      checkAttestationState(oidcClientResponse.clientId, ClientAttestationState.PENDING, null).also {
        it.attestationType.shouldBeNull()
      }
      // A_30086: registered, but not yet usable for resource access — the attestation is still outstanding.
      oidcClientResponse.status shouldBe ClientRegistrationState.REGISTERED

      val (_, newAccessToken, refreshToken) = testExchangeToken(
          subjectToken = smbcToken,
          clientId = oidcClientResponse.clientId,
          clientAssertion = jws,
          requestedClientScope = SCOPE_ZETA_TEST
      )

      newAccessToken.scope shouldContain SCOPE_ZETA_TEST
      refreshToken.scope shouldContain SCOPE_ZETA_TEST

      checkAttestationState(oidcClientResponse.clientId, ClientAttestationState.VALID, now).also {
        it.attestationType shouldBe AttestationType.SOFTWARE
      }

      // A_30086: the token exchange attested the client, so a re-read of the registration reports it as active.
      keycloakWebClient
          .getClientOIDC(oidcClientResponse.clientId, oidcClientResponse.registrationAccessToken)
          .shouldBeRight()
          .responseObject
          .status shouldBe ClientRegistrationState.ACTIVE
    }

    // Realm client policy "reject-implicit-grant" (auto-configure): a requested implicit flow is switched off, not rejected
    test("Client registration switches off the implicit flow requested via response_types") {
      val request =
          ClientRegistrationRequestFactory.createClientRegistrationRequest(
              clientAssertionTokenGenerator.keys,
              null,
              responseTypes = listOf(OIDCResponseType.TOKEN, OIDCResponseType.CODE),
          )

      val response = keycloakWebClient.registerClientOIDC(clientRegistrationRequest = request).shouldBeRight().responseObject

      response.responseTypes shouldContain OIDCResponseType.CODE
      response.responseTypes shouldNotContain OIDCResponseType.ID_TOKEN
    }

    test("Client registration expiration") {
      setZetaClientClientLastAccess()
      keycloakWebClient.enableClientJob(true)

      try {
        lookupClientData(oidcClientResponse.clientId).shouldNotBeNull()
        lookupClient(oidcClientResponse.clientId) shouldBe true

        // Poll until the client is expired instead of fixed sleep to avoid flakiness
        withClue("Client still present after 30 seconds (id=${oidcClientResponse.clientId})") {
          val config = eventuallyConfig {
            duration = 30.seconds
            interval = 2.seconds
            initialDelay = 2.seconds
          }

          eventually(config) { lookupClient(oidcClientResponse.clientId) shouldBe false }
        }

        lookupClientData(oidcClientResponse.clientId).shouldBeNull()
      } finally {
        keycloakWebClient.enableClientJob(false)
      }
    }

    // Otherwise a client registered without redirect_uris could add them (and the standard flow) afterwards while its ZETA data still says SMC_B
    test("RFC 7592 update and delete are not available on the registration endpoint") {
      val clientId = oidcClientResponse.clientId
      val uri = keycloakWebClient.uriBuilder().createUri("$OIDC_CLIENT_REGISTRATION_PATH/$clientId", ZETA_REALM)
      val authorization = "$AUTH_HEADER_PREFIX${oidcClientResponse.registrationAccessToken}"
      val body = """{"redirect_uris":["https://attacker.example/cb"],"client_name":"attacker"}"""

      listOf(
          RequestBuilder.put(uri).addHeader(CONTENT_TYPE, APPLICATION_JSON.mimeType).setEntity(StringEntity(body, Charsets.UTF_8)),
          RequestBuilder.delete(uri),
      ).forEach { request ->
        keycloakWebClient.httpClient().execute(request.addHeader(AUTHORIZATION, authorization).build()).use {
          withClue("${request.method} on the registration endpoint: ${EntityUtils.toString(it.entity)}") {
            it.statusLine.statusCode shouldBe SC_METHOD_NOT_ALLOWED
          }
        }
      }

      // The registration is untouched: still readable, no redirect URIs, client data still there
      keycloakWebClient.getClientOIDC(clientId, oidcClientResponse.registrationAccessToken).shouldBeRight().responseObject.redirectUris.orEmpty().shouldBeEmpty()
      lookupClient(clientId) shouldBe true
      lookupClientData(clientId).shouldNotBeNull()
    }

    test("Certificate signature validation fails") {
      val certificate =
          CertificateGenerator(
              subjectName = smcb.leafCertificate.subjectX500Principal.toString(),
              subjectKeyPair = smcb.subjectKeyPair,
              issuerName = smcb.leafCertificate.issuerX500Principal.toString(),
              issuerKeyPair = smcb.subjectKeyPair,
              isCA = false,
          )
              .buildCertificate()

      smbcToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              audiences = smcbTokenAudience,
              subject = smcb.telematikId,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(certificate),
          )

      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "certificate does not verify"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("Unknown certificate issuer") {
      val certificate =
          CertificateGenerator(
              subjectName = DN_PRAXIS,
              subjectKeyPair = smcb.subjectKeyPair,
              issuerName = DN_GEMATIK,
              issuerKeyPair = generateKeyPair(),
              isCA = false,
          )
              .buildCertificate()
      smbcToken =
          smcb.smcbTokenGenerator.generateSMCBToken(
              nonceString = nonce,
              subject = smcb.telematikId,
              audiences = smcbTokenAudience,
              issuer = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              certificateChain = listOf(certificate),
          )

      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_TOKEN
        it.errorDescription shouldContain "issuer not found"
        it.statusCode shouldBe SC_FORBIDDEN
      }
    }

    test("Token exchange fails, because of unknown public key signature of client assertion JWT") {
      val jws = ClientAssertionTokenGenerator().generateClientAssertion(oidcClientResponse, nonce) // Generates (unknowwn) new keys and certificates

      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Unable to load public key"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
    }

    test("Token exchange fails, because of wrong signature of client assertion JWT") {
      val originalJWS = jws
      val tokenParts = originalJWS.split('.').also { it.size shouldBe 3 }
      val corruptedSignature =
          tokenParts[2]
              .fromBase64()
              .apply {
                this[0] = 123
                this[42] = 123
                this[this.size - 1] = 123
              }
              .toBase64()

      testExchangeToken(
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
          clientAssertionTokenGenerator.generateClientAssertion(
              clientId = "jens",
              subject = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              audiences = smcbTokenAudience,
              nonceString = nonce,
          )

      /**
       * Issuer must match subject,
       *
       * see [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       */
      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe INVALID_CLIENT
        it.statusCode shouldBe SC_UNAUTHORIZED
      }
    }

    test("Token exchange fails because of wrong subject in client_assertion") {
      val invalidJWS =
          clientAssertionTokenGenerator.generateClientAssertion(
              clientId = oidcClientResponse.clientId,
              subject = "jens",
              issuedFor = oidcClientResponse.clientId,
              audiences = listOf(oidcClientResponse.clientId),
              nonceString = nonce,
          )

      /**
       * Issuer must match subject, see
       *
       * [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       */
      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe INVALID_CLIENT
        it.statusCode shouldBe SC_UNAUTHORIZED
      }
    }

    test("Token exchange fails because of wrong audience in JWS in client_assertion") {
      /**
       * audience must match token audience (http://.../zeta-guard), see
       * [org.keycloak.authentication.authenticators.client.AbstractJWTClientValidator.validateClient]
       */
      val invalidJWS =
          clientAssertionTokenGenerator.generateClientAssertion(
              clientId = oidcClientResponse.clientId,
              subject = oidcClientResponse.clientId,
              issuedFor = oidcClientResponse.clientId,
              audiences = listOf("jens"),
              nonceString = nonce,
          )
      testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = invalidJWS) {
        it.error shouldBe INVALID_CLIENT
        it.errorDescription shouldBe "Invalid token audience"
        it.statusCode shouldBe SC_BAD_REQUEST
      }
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

  private fun lookupClientData(clientId: String): ZetaGuardClientData? {
    return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
      val dataService = ZetaGuardDataService { it.createEntityManager() }
      dataService.findClientData(clientId)
    }
  }

  private fun checkAttestationState(
      clientId: String,
      expectedState: ClientAttestationState,
      expectedAccessTime: LocalDateTime?
  ): ZetaGuardClientData {
    val clientData = lookupClientData(clientId).shouldNotBeNull()
    clientData.attestationState shouldBe expectedState

    if (expectedAccessTime != null) {
      clientData.lastAccess shouldBeAfter expectedAccessTime
    }

    return clientData
  }
}

fun KeycloakWebClient.enableClientJob(enabled: Boolean) {
  withKeycloak(clientId = ADMIN_CLIENT) {
    val realmResource = realm(ZETA_REALM)
    val realmRepresentation = realmResource.toRepresentation()

    realmRepresentation.attributes[ATTRIBUTE_REALM_CLIENT_JOB_DISABLED] = (!enabled).toString()

    realmResource.update(realmRepresentation)
  }
}

fun setZetaClientClientLastAccess() {
  return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
    val entityManager = it.createEntityManager()
    entityManager.transaction.begin()
    val dataService = ZetaGuardDataService { entityManager }

    // Reset to ensure it is not expired
    dataService.findClientData(ZETA_CLIENT)?.apply { lastAccess = currentTime().plusDays(1) }
    entityManager.transaction.commit()
  }
}
