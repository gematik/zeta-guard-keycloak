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
import de.gematik.zeta.zetaguard.keycloak.commons.DN_GEMATIK
import de.gematik.zeta.zetaguard.keycloak.commons.DN_PRAXIS
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REALM_CLIENT_JOB_DISABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
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
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.time.LocalDateTime
import kotlin.time.Duration.Companion.seconds
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_FORBIDDEN
import org.apache.http.HttpStatus.SC_UNAUTHORIZED
import org.keycloak.OAuthErrorException.INVALID_CLIENT
import org.keycloak.OAuthErrorException.INVALID_TOKEN
import org.keycloak.models.jpa.entities.ClientAttributeEntity
import org.keycloak.models.jpa.entities.ClientEntity
import org.keycloak.models.jpa.entities.ClientScopeAttributeEntity
import org.keycloak.models.jpa.entities.ClientScopeEntity
import org.keycloak.models.jpa.entities.ProtocolMapperEntity
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_REGISTRATION_ACCESS_TOKEN

class ClientRegistrationIT : ZetaGuardFunSpecIT() {
  init {
    var nonce = ""
    var smbcToken = ""
    var jws = ""
    var oidcClientResponse = OIDCClientRepresentation()

    beforeTest {
      oidcClientResponse = keycloakWebClient.createClientOIDC(clientAssertionTokenGenerator.keys.jwks).shouldBeRight().reponseObject
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

      checkAttestationState(oidcClientResponse.clientId, ClientAttestationState.PENDING, null)

      val accessTokenResponse = testExchangeToken(subjectToken = smbcToken, clientId = oidcClientResponse.clientId, clientAssertion = jws)

      accessTokenResponse.token.shouldNotBeNull()
      accessTokenResponse.token.checkTokenHeader()
      accessTokenResponse.refreshToken.shouldNotBeNull()
      accessTokenResponse.refreshToken.checkTokenHeader()

      checkAttestationState(oidcClientResponse.clientId, ClientAttestationState.VALID, now)
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
    val entityClasses = arrayOf(ZetaGuardUserData::class.java, ZetaGuardClientData::class.java)

    return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
      val dataService = ZetaGuardDataService { it.createEntityManager() }
      dataService.findClientData(clientId)
    }
  }

  private fun checkAttestationState(clientId: String, expectedState: ClientAttestationState, expectedAccessTime: LocalDateTime?) {
    val clientData = lookupClientData(clientId).shouldNotBeNull()
    clientData.attestationState shouldBe expectedState

    if (expectedAccessTime != null) {
      clientData.lastAccess shouldBeAfter expectedAccessTime
    }
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
  val entityClasses = arrayOf(ZetaGuardUserData::class.java, ZetaGuardClientData::class.java)

  return JpaEntityManagerFactory(dbhost, dbport, *entityClasses).use {
    val entityManager = it.createEntityManager()
    entityManager.transaction.begin()
    val dataService = ZetaGuardDataService { entityManager }

    // Reset to ensure it is not expired
    dataService.findClientData(ZETA_CLIENT)?.apply { lastAccess = currentTime().plusDays(1) }
    entityManager.transaction.commit()
  }
}
