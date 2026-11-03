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

import arrow.core.Either
import de.gematik.zeta.zetaguard.keycloak.commons.ClientRegistrationRequestFactory
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_TARGET_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_BIRTHDATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_DISPLAY_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_COLLECT_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_VERIFY_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_COMMON_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_IP_ADDRESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_BINDING_MODE
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_EMAIL_HINT
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.fromBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.gematik.zeta.zetaguard.keycloak.it.Docker.gsiServerHost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.gsiServerPort
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kchost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kcport
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLog
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import de.spree.keycloak.commons.integrityProviderEnabled
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.nondeterministic.eventually
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotBeBlank
import java.sql.DriverManager
import java.util.UUID
import kotlin.time.Duration.Companion.seconds
import org.apache.http.HttpStatus.SC_ACCEPTED
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_CONFLICT
import org.apache.http.HttpStatus.SC_NOT_FOUND
import org.apache.http.HttpStatus.SC_NO_CONTENT
import org.apache.http.HttpStatus.SC_OK
import org.apache.http.HttpStatus.SC_UNAUTHORIZED
import org.keycloak.OAuthErrorException
import org.keycloak.common.util.SecretGenerator
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.protocol.oidc.utils.OIDCResponseType
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.util.JsonSerialization
import org.keycloak.util.JsonSerialization.readValue

/** One SekIDP user per attestation type, so each runs the email binding sequence (collect_email → verify_otp → bound) from scratch. */
private data class Persona(
    val attestationType: AttestationType,
    val kvnr: String,
    val email: String,
    val displayName: String,
    val birthDate: String
) {
  /** Target of the email-change tests; starts with another letter so the masked `email_hint` differs from [email]. */
  val otherEmail: String
    get() = "other-$email"
}

// What gsi-server's test identity for [KVNR] releases as urn:telematik:claims:display_name and birthdate, see versicherte.gesundheitsid.json.

// Fragments of the notification texts, see ClientNotifier and EmailChangeNotifier
private const val N1_CLIENT_ADDED = "wurde ein neues Ger"
private const val N3_CLIENT_REMOVED = "wurde von Ihrer Identit"
private const val N5_EMAIL_CHANGED = "verknüpfte E-Mail-Adresse wurde geändert"
private val MAIL_TIMEOUT = 10.seconds

private val PERSONAS = listOf(
    Persona(AttestationType.APPLE, "P179293933", "kvnr-user@zeta-it.invalid", "Ditte Weitzenböck", "2000-06-05"),
    Persona(AttestationType.ANDROID, "D700912910", "kvnr-android-user@zeta-it.invalid", "Jenni van den Berge", "1941-05-23"),
    Persona(AttestationType.SOFTWARE, "R302790019", "ti-ref-3@prehapp.de", "Karyn Friderich", "2002-01-23")
)

/**
 * Happy-path proof of the full SekIDP broker chain against the real gematik reference images (gsi-fedmaster,
 * gsi-server): DCR → outer PAR → `/authorize` → sectoral IdP login → cookie-free broker relay → token redemption.
 */
class SekIdpBrokerFlowIT : ZetaGuardFunSpecIT() {
  private val flowClient by lazy { SekIdpFlowClient(kchost, kcport, gsiServerHost, gsiServerPort) }
  private val mailpit = MailpitClient(Docker.mailpitUrl)
  private var nonce: ByteArray = ByteArray(0)

  init {
    // Fills Keycloak's federation caches (fedmaster + our own entity statement) ahead of the real test, whose
    // registration TTL (4s) leaves no room for the ~10s cold-start federation fetch.
    beforeSpec {
      Either.catch { PERSONAS.first().runFlowUpToSekIdpRedirect() }.onLeft { Docker.log.warn("SekIDP warm-up fail", it) }
    }

    beforeEach {
      nonce = keycloakWebClient.getNonce().shouldBeRight().responseObject.fromBase64()
    }

    PERSONAS.forEach { persona ->
      context("${persona.attestationType}") {
        with(persona) {
          test("happy path: DCR → PAR → SekIDP login → broker relay → token") {
            val client = registerClient()
            val codeVerifier = PkceUtils.generateCodeVerifier()
            val codeChallenge = PkceUtils.generateS256CodeChallenge(codeVerifier)
            val state = SecretGenerator.getInstance().generateSecureID()

            val requestUri = flowClient.pushAuthorizationRequest(client, codeChallenge, state).requestUri
            val innerRequestUri = flowClient.authorize(requestUri, client.clientId)
            val (code, sekIdpState) = flowClient.sekIdpLogin(innerRequestUri, kvnr)
            val guardCode = flowClient.relayBrokerCallback(code, sekIdpState)
            val result = flowClient.exchangeCodeForToken(client, guardCode, codeVerifier)

            result.statusCode shouldBe SC_OK
            result.response.token.shouldNotBeBlank()

            val accessToken = result.response.token.toAccessToken()

            accessToken.subject.shouldNotBeBlank()
            // A_26973-03: commonName and birthdate are taken from the SekIDP's ID token.
            accessToken.otherClaims[CLAIM_COMMON_NAME] shouldBe displayName
            accessToken.birthdate shouldBe birthDate

            // A_26973-02: the user data of the ID token is stored at the user, encrypted by the integrity provider if enabled.
            val attributes = lookupUser(kvnr.toSpicyHash().lowercase()).attributes.associate { it.name to it.value }
            mapOf(ATTRIBUTE_MOBILEUSER_KVNR to kvnr, ATTRIBUTE_MOBILEUSER_DISPLAY_NAME to displayName, ATTRIBUTE_MOBILEUSER_BIRTHDATE to birthDate)
                .forEach { (name, plaintext) ->
                  val stored = attributes[name].shouldNotBeNull()
                  if (integrityProviderEnabled) stored shouldNotBe plaintext else stored shouldBe plaintext
                }
            attributes[ATTRIBUTE_MOBILEUSER_ACR].shouldBeNull()
          }

          // First login: the client is unbound, so only the reduced email-binding token is issued (no refresh token).
          test("first login issues a reduced email-binding token without refresh token") {
            val tokens = loginAndGetTokens(registerClient())

            tokens.response.refreshToken.shouldBeNull()
            tokens.response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] shouldBe BINDING_MODE_COLLECT_EMAIL
            tokens.response.scope.split(' ') shouldContainAll setOf(SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)

            // The binding token must satisfy the PEP like a regular token (claim mapper on zeta:email-verify).
            val binding = tokens.response.token.toAccessToken()
            binding.otherClaims[CLAIM_COMMON_NAME].shouldNotBeNull()
            binding.otherClaims[CLAIM_IP_ADDRESS].shouldNotBeNull()
            binding.otherClaims[CLAIM_CLIENT_ID].shouldNotBeNull()
          }

          // Runs after the first-login test: the same user (kvnr) ends up with a verified email.
          test("collect_email: user submits an email and verifies the OTP, the client becomes bound") {
            val client = registerClient()
            val binding = loginAndGetTokens(client).response.token

            flowClient.bindEmail(binding, email).statusCode shouldBe SC_ACCEPTED
            val otp = mailpit.latestOtp(email)

            // Submitted, but not verified yet: not released to resource servers.
            flowClient.userInfoEmail(kvnr, ResourceServerPki.trustedResourceServer).statusCode shouldBe SC_NOT_FOUND

            flowClient.verifyEmailOtp(binding, "000000").statusCode shouldBe SC_BAD_REQUEST
            val verified = flowClient.verifyEmailOtp(binding, otp)

            verified.statusCode shouldBe SC_OK
            verified.body shouldContain "bound"
          }

          // The user's email is verified by now: a resource server authenticated via mTLS may fetch it.
          test("userinfo/email releases the verified email to a trusted resource server") {
            val result = flowClient.userInfoEmail(kvnr, ResourceServerPki.trustedResourceServer)

            result.statusCode shouldBe SC_OK
            result.body shouldContain email
          }

          test("userinfo/email rejects resource servers without a trusted client certificate") {
            flowClient.userInfoEmail(kvnr, null).statusCode shouldBe SC_UNAUTHORIZED
            flowClient.userInfoEmail(kvnr, ResourceServerPki.foreignResourceServer).statusCode shouldBe SC_UNAUTHORIZED
          }

          test("userinfo/email answers 404 for an unknown or missing identifier") {
            flowClient.userInfoEmail("X999999999", ResourceServerPki.trustedResourceServer).statusCode shouldBe SC_NOT_FOUND
            flowClient.userInfoEmail(null, ResourceServerPki.trustedResourceServer).statusCode shouldBe SC_NOT_FOUND
          }

          // The user's email is verified by now, so a new client only has to confirm the OTP sent to that address.
          test("verify_otp: new client of a verified user only confirms the OTP") {
            val tokens = loginAndGetTokens(registerClient())

            tokens.response.refreshToken.shouldBeNull()
            tokens.response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] shouldBe BINDING_MODE_VERIFY_OTP
            tokens.response.otherClaims[RESPONSE_MEMBER_EMAIL_HINT].shouldNotBeNull()
            tokens.response.scope.split(' ').also {
              it shouldContain SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
              it shouldNotContain SCOPE_EMAIL_BINDING
            }

            flowClient.verifyEmailOtp(tokens.response.token, mailpit.latestOtp(email)).statusCode shouldBe SC_OK
          }

          test("bound client gets full tokens with refresh token and without email-binding scopes") {
            val client = registerClient()
            val binding = loginAndGetTokens(client).response.token
            flowClient.verifyEmailOtp(binding, mailpit.latestOtp(email)).statusCode shouldBe SC_OK

            val full = loginAndGetTokens(client)

            full.response.refreshToken.shouldNotBeNull()
            full.response.otherClaims[RESPONSE_MEMBER_BINDING_MODE].shouldBeNull()
            full.response.scope.split(' ').also {
              it shouldNotContain SCOPE_EMAIL_BINDING
              it shouldNotContain SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
            }
          }

          test("refresh issues a new token set for a bound client") {
            val client = registerClient()
            val binding = loginAndGetTokens(client).response.token
            flowClient.verifyEmailOtp(binding, mailpit.latestOtp(email)).statusCode shouldBe SC_OK
            val full = loginAndGetTokens(client)

            val refreshed = flowClient.refreshToken(client, full.response.refreshToken.shouldNotBeNull())

            refreshed.statusCode shouldBe SC_OK
            refreshed.response.token.shouldNotBeBlank()
            refreshed.response.refreshToken.shouldNotBeNull()
          }

          // A_29848: admin revokes token, so its refresh token must no longer work.
          test("refresh is rejected once the session has been terminated") {
            val client = registerClient()
            val binding = loginAndGetTokens(client).response.token
            flowClient.verifyEmailOtp(binding, mailpit.latestOtp(email)).statusCode shouldBe SC_OK
            val full = loginAndGetTokens(client)
            val sessionId = full.response.token.toAccessToken().sessionId.shouldNotBeNull()

            keycloakWebClient.adminRevokeSession(sessionId).shouldBeRight()
            val refreshed = flowClient.refreshToken(client, full.response.refreshToken.shouldNotBeNull())

            refreshed.statusCode shouldBe SC_BAD_REQUEST
            refreshed.body shouldContain OAuthErrorException.INVALID_GRANT
          }

          test("identity/email rejects a request that did not come through the PEP") {
            val client = registerClient()
            bindClient(client)
            val full = loginAndGetTokens(client).response

            flowClient.changeEmail(null, otherEmail).statusCode shouldBe SC_UNAUTHORIZED
            flowClient.verifyEmailChangeOtp(null, "000000").statusCode shouldBe SC_UNAUTHORIZED
            flowClient.resendEmailChangeOtp(null).statusCode shouldBe SC_UNAUTHORIZED
            // nothing pending: the PEP-forwarded caller alone does not open a challenge
            flowClient.verifyEmailChangeOtp(full.token, "000000").statusCode shouldBe SC_CONFLICT
          }

          // The identity's address is switched to otherEmail and back, so the following tests keep seeing email.
          test("email change: the code goes to the new address, verify switches the identity-wide email") {
            val client = registerClient()
            bindClient(client)
            val full = loginAndGetTokens(client).response

            val challenge = flowClient.changeEmail(full.token, otherEmail)
            challenge.statusCode shouldBe SC_ACCEPTED
            challenge.body shouldContain "pending"

            flowClient.verifyEmailChangeOtp(full.token, "000000").statusCode shouldBe SC_BAD_REQUEST
            flowClient.resendEmailChangeOtp(full.token).statusCode shouldBe SC_ACCEPTED
            val changed = notifications(email, N5_EMAIL_CHANGED)
            val verified = flowClient.verifyEmailChangeOtp(full.token, mailpit.latestOtp(otherEmail))
            verified.statusCode shouldBe SC_OK
            verified.body shouldContain "verified"
            // N5 goes to the previous address only
            eventually(MAIL_TIMEOUT) { notifications(email, N5_EMAIL_CHANGED) shouldBe changed + 1 }

            // A new client of the identity now gets its registration code at the new address (second DCR in this test: fresh nonce)
            nonce = keycloakWebClient.getNonce().shouldBeRight().responseObject.fromBase64()
            val tokens = loginAndGetTokens(registerClient()).response
            tokens.otherClaims[RESPONSE_MEMBER_BINDING_MODE] shouldBe BINDING_MODE_VERIFY_OTP
            flowClient.verifyEmailOtp(tokens.token, mailpit.latestOtp(otherEmail)).statusCode shouldBe SC_OK

            flowClient.changeEmail(full.token, email).statusCode shouldBe SC_ACCEPTED
            flowClient.verifyEmailChangeOtp(full.token, mailpit.latestOtp(email)).statusCode shouldBe SC_OK
          }

          test("deleting a lost device revokes its sessions, the identity's other devices stay logged in") {
            val (phone, phoneTokens) = boundClientWithTokens()
            nonce = keycloakWebClient.getNonce().shouldBeRight().responseObject.fromBase64()
            val added = notifications(email, N1_CLIENT_ADDED)
            val (lost, lostTokens) = boundClientWithTokens()
            val lostSid = lostTokens.token.toAccessToken().sessionId.shouldNotBeNull()
            lostSid shouldNotBe phoneTokens.token.toAccessToken().sessionId

            // A_<tas>007: another device of an existing identity is announced to the identity's address (at least: the phone's own N1 may still be
            // on its way, its identity exists from the tests before)
            eventually(MAIL_TIMEOUT) { notifications(email, N1_CLIENT_ADDED) shouldBeGreaterThan added }
            listedClientIds(phoneTokens.token) shouldContainAll listOf(phone.clientId, lost.clientId)

            val removed = notifications(email, N3_CLIENT_REMOVED)
            RevocationStream(keycloakWebClient).use { stream ->
              flowClient.deleteClient(phoneTokens.token, lost.clientId).statusCode shouldBe SC_NO_CONTENT

              stream.awaitBlock(lostSid)[RevocationStream.FIELD_WHAT] shouldBe lostSid
            }
            eventually(MAIL_TIMEOUT) { notifications(email, N3_CLIENT_REMOVED) shouldBe removed + 1 }
            // A_<tas>008: both calls are in the admin event log, the end user as actor
            adminEventsAbout(lost.clientId).map { it.operationType } shouldContainExactlyInAnyOrder listOf(OperationType.CREATE, OperationType.DELETE)
            persistedSessions(lostSid).shouldBeEmpty()
            listedClientIds(phoneTokens.token).also {
              it shouldContain phone.clientId
              it shouldNotContain lost.clientId
            }
            flowClient.refreshToken(lost, lostTokens.refreshToken.shouldNotBeNull()).statusCode shouldNotBe SC_OK
            flowClient.refreshToken(phone, phoneTokens.refreshToken.shouldNotBeNull()).statusCode shouldBe SC_OK
          }

          test("only the identity's own mobile clients can be deleted, and only through the PEP") {
            val (_, tokens) = boundClientWithTokens()

            flowClient.deleteClient(tokens.token, UUID.randomUUID().toString()).statusCode shouldBe SC_NOT_FOUND
            flowClient.deleteClient(null, tokens.token.toAccessToken().issuedFor).statusCode shouldBe SC_UNAUTHORIZED
          }

          test("outer PAR hands out a request_uri valid for 5 seconds") {
            val codeChallenge = PkceUtils.generateS256CodeChallenge(PkceUtils.generateCodeVerifier())
            val state = SecretGenerator.getInstance().generateSecureID()

            flowClient.pushAuthorizationRequest(registerClient(), codeChallenge, state).expiresIn shouldBe 5
          }

          test("outer PAR without idp_iss is rejected by the outer PAR policy") {
            val codeChallenge = PkceUtils.generateS256CodeChallenge(PkceUtils.generateCodeVerifier())
            val state = SecretGenerator.getInstance().generateSecureID()

            val response = flowClient.postPushedAuthorizationRequest(flowClient.parParameters(registerClient(), codeChallenge, state) - "idp_iss")

            response.statusCode shouldBe SC_BAD_REQUEST
          }

          test("outer PAR with an unregistered oidc_redirect_uri is rejected by the outer PAR policy") {
            val codeChallenge = PkceUtils.generateS256CodeChallenge(PkceUtils.generateCodeVerifier())
            val state = SecretGenerator.getInstance().generateSecureID()

            val parameters =
                flowClient.parParameters(registerClient(), codeChallenge, state) + ("oidc_redirect_uri" to "https://attacker.invalid/cb/oidc")
            val response = flowClient.postPushedAuthorizationRequest(parameters)

            response.statusCode shouldBe SC_BAD_REQUEST
          }
        }
      }
    }
  }

  /** Binds [client] to [Persona.email] whether or not the identity already has a verified address, so tests can run alone. */
  private fun Persona.bindClient(client: RegisteredClient) {
    val tokens = loginAndGetTokens(client).response
    if (tokens.otherClaims[RESPONSE_MEMBER_BINDING_MODE] == BINDING_MODE_COLLECT_EMAIL) {
      flowClient.bindEmail(tokens.token, email).statusCode shouldBe SC_ACCEPTED
    }
    flowClient.verifyEmailOtp(tokens.token, mailpit.latestOtp(email)).statusCode shouldBe SC_OK
  }

  /** A freshly registered client whose email binding is confirmed, and its full token set. */
  private fun Persona.boundClientWithTokens(): Pair<RegisteredClient, AccessTokenResponse> {
    val client = registerClient()
    bindClient(client)
    val tokens = loginAndGetTokens(client).response

    return client to tokens
  }

  /** The admin event log entries of ZETA client management calls about [clientId]. */
  private fun adminEventsAbout(clientId: String): List<AdminEvent> =
      JpaEntityManagerFactory(dbhost, dbport, AdminEventLog::class.java).use { factory ->
        AdminEventLogStorageService { factory.createEntityManager() }
            .findAll()
            .map { readValue(it.event, AdminEvent::class.java) }
            .filter { it.details?.get(DETAIL_ZETA_TARGET_CLIENT_ID) == clientId }
      }

  /** How many notifications containing [text] [recipient] has received so far. */
  private fun notifications(recipient: String, text: String) = mailpit.plainBodies(recipient).count { text in it }

  private fun listedClientIds(accessToken: String): List<String> {
    val listed = flowClient.listClients(accessToken).also { it.statusCode shouldBe SC_OK }

    return JsonSerialization.mapper.readTree(listed.body).map { it.path("client_id").asText() }
  }

  /** The OFFLINE_FLAG of every persisted session with id [sid]: persistent user sessions keep online and offline sessions in one table. */
  private fun persistedSessions(sid: String): List<String> =
      DriverManager.getConnection(Docker.jdbcUrl).use { connection ->
        connection.prepareStatement("SELECT offline_flag FROM offline_user_session WHERE user_session_id = ?").use { statement ->
          statement.setString(1, sid)
          statement.executeQuery().use { rows -> generateSequence { if (rows.next()) rows.getString(1) else null }.toList() }
        }
      }

  private fun Persona.loginAndGetTokens(client: RegisteredClient): TokenResult {
    val codeVerifier = PkceUtils.generateCodeVerifier()
    val codeChallenge = PkceUtils.generateS256CodeChallenge(codeVerifier)
    val state = SecretGenerator.getInstance().generateSecureID()

    val requestUri = flowClient.pushAuthorizationRequest(client, codeChallenge, state).requestUri
    val innerRequestUri = flowClient.authorize(requestUri, client.clientId)
    val (code, sekIdpState) = flowClient.sekIdpLogin(innerRequestUri, kvnr)
    val guardCode = flowClient.relayBrokerCallback(code, sekIdpState)

    return flowClient.exchangeCodeForToken(client, guardCode, codeVerifier).also { it.statusCode shouldBe SC_OK }
  }

  private fun Persona.registerClient(): RegisteredClient {
    val request = ClientRegistrationRequestFactory.createClientRegistrationRequest(
        clientAssertionTokenGenerator.keys,
        nonce,
        redirectUris = listOf(SEKIDP_OUTER_REDIRECT_URI, SEKIDP_OIDC_REDIRECT_URI),
        grantTypes = SEKIDP_VALID_GRANT_TYPES,
        responseTypes = listOf(OIDCResponseType.CODE),
        attestationType = attestationType
    )
    val representation = keycloakWebClient.registerClientOIDC(clientRegistrationRequest = request).shouldBeRight().responseObject

    return RegisteredClient(representation, clientAssertionTokenGenerator)
  }

  private fun Persona.runFlowUpToSekIdpRedirect() {
    val client = registerClient()
    val codeChallenge = PkceUtils.generateS256CodeChallenge(PkceUtils.generateCodeVerifier())
    val state = SecretGenerator.getInstance().generateSecureID()
    val requestUri = flowClient.pushAuthorizationRequest(client, codeChallenge, state).requestUri

    flowClient.authorize(requestUri, client.clientId)
  }
}
