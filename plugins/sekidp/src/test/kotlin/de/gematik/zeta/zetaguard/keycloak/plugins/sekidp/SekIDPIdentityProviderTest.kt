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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_BIRTHDATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_DISPLAY_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ORGANIZATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_MTLS_HTTP_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.lookupHttpClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.plugins.sekidp.FederationEndpoint.SIGNED_JWKS
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.maps.shouldNotContainKey
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldStartWith
import io.mockk.every
import io.mockk.just
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.unmockkConstructor
import io.mockk.unmockkStatic
import io.mockk.verify
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityBrokerException
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.jose.jws.JWSInput
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.representations.IDToken
import org.keycloak.services.ErrorResponseException
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization

private const val NOTE_IDP_ISS = AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "idp_iss"

/** Matches Keycloak's private `OIDCIdentityProvider.BROKER_NONCE_PARAM`, which the base class reads and writes. */
private const val NOTE_BROKER_NONCE = "BROKER_NONCE"

/** Matches Keycloak's private `BROKER_CODE_CHALLENGE`, which despite its name stores the code *verifier*. */
private const val NOTE_BROKER_CODE_VERIFIER = "BROKER_CODE_CHALLENGE"
private const val NOTE_BROKER_CODE_CHALLENGE_METHOD = "BROKER_CODE_CHALLENGE_METHOD"

/** The provider's own note carrying the inner redirect_uri, reused verbatim at the token request. */
private const val NOTE_OIDC_REDIRECT_URI = "SEKIDP_OIDC_REDIRECT_URI"

/** The client's `oidc_redirect_uri` request parameter, as the authorization endpoint stores it. */
private const val NOTE_OIDC_REDIRECT_URI_PARAM = AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + "oidc_redirect_uri"

/** The `aud` of every ID token [FederationMock] issues. `validateToken` checks it against the configured client id. */
private const val CLIENT_ID = "zeta-guard"

// Claim names are spelled out here because they are wire format. A test that restates them catches a rename of the
// production constant.
private const val CLAIM_KVNR = "urn:telematik:claims:id"
private const val CLAIM_PROFESSION = "urn:telematik:claims:profession"
private const val CLAIM_ORGANIZATION = "urn:telematik:claims:organization"
private const val CLAIM_DISPLAY_NAME = "urn:telematik:claims:display_name"
private const val CLAIM_BIRTHDATE = "birthdate"
private const val CLAIM_ACR = "acr"
private const val CLAIM_AMR = "amr"
private const val CLAIM_NONCE = IDToken.NONCE

private const val KVNR = "X110411675"
private const val DISPLAY_NAME = "Dr. Erika Mustermann-Gabler"

/** What the stubbed `toSpicyHash()` answers for [KVNR]. Real hashing needs the `SMCB_HASHING_PEPPER` environment variable. */
private const val HASHED_KVNR = "$KVNR-hashed"

private const val ACR_HIGH = "gematik-ehealth-loa-high"
private const val NONCE = "nonce-from-the-authorization-request"

private const val OIDC_REDIRECT_URI = "https://relying-party.example/oidc/callback"
private const val DEFAULT_SCOPE = "urn:telematik:display_name urn:telematik:versicherter urn:telematik:geburtsdatum openid"

/** The relay state Keycloak minted for the outer flow, which the provider passes through untouched. */
private const val OUTER_STATE = "outer-relay-state"

/**
 * Component tests for [SekIDPIdentityProvider] against a localhost [FederationMock], without Keycloak or Docker.
 *
 * Only what the provider adds on top of the trust chain belongs here: reading `idp_iss` off the authentication session,
 * turning a resolved chain into a broker decision. Everything about the chain itself is in [FederationTest].
 */
class SekIDPIdentityProviderTest : ZetaGuardFunSpec() {

  /** The client the provider takes from the session, one per test. */
  private lateinit var httpClient: CloseableHttpClient

  init {
    beforeEach {
      httpClient = HttpClients.createDefault()
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      // The real hashing needs the SMCB_HASHING_PEPPER environment variable no test sets. Answering for exactly the
      // KVNR is what pins it as the hashed input: anything else falls through to the real function and fails.
      every { KVNR.toSpicyHash() } returns HASHED_KVNR
      mockkConstructor(AuthSessionCookieValueByStateAs::class)
      every { anyConstructed<AuthSessionCookieValueByStateAs>().store(any(), any()) } just runs
    }

    afterEach {
      unmockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      unmockkConstructor(AuthSessionCookieValueByStateAs::class)
    }

    context("verify — brokering around the trust chain (A_29672)") {
      test("accepts an ID token the trust chain vouches for") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          provider.verify(JWSInput(sekIdp.idToken())) shouldBe true
        }
      }

      test("turns a broken trust chain into a rejection rather than an error") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          sekIdp.serve(SIGNED_JWKS, sekIdp.protocolKey.sign(sekIdp.defaultSignedJwksBody()))

          provider.verify(JWSInput(sekIdp.idToken())) shouldBe false
        }
      }

      test("rejects the token when the authentication session names no idp_iss") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp, sessionFor(sekIdp, idpIss = null))

          provider.verify(JWSInput(sekIdp.idToken())) shouldBe false

          // Without an issuer there is nothing to resolve, so the chain is never entered.
          sekIdp.requestedPaths.shouldBeEmpty()
        }
      }
    }

    context("identity — claims of the ID token (A_29671, A_29672)") {
      test("derives the username from the KVNR") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse())

          identity.modelUsername shouldBe HASHED_KVNR
          identity.contextData[ATTRIBUTE_MOBILEUSER_KVNR] shouldBe KVNR
          // getUsername() lowercases unless the IdP sets caseSensitiveOriginalUsername, so the KVNR's leading letter keeps
          // the hash and its lowercase form distinct here. Only modelUsername carries the hash verbatim.
          identity.username shouldBe HASHED_KVNR.lowercase()
        }
      }

      test("carries acr, amr and the optional telematik claims into the context data") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity =
              provider.getFederatedIdentity(
                  sekIdp.tokenResponse(
                      CLAIM_AMR to listOf("mfa", "sc"),
                      CLAIM_PROFESSION to "1.2.276.0.76.4.49",
                      CLAIM_ORGANIZATION to "Praxis Musterarzt",
                  ))

          identity.contextData[ATTRIBUTE_MOBILEUSER_ACR] shouldBe ACR_HIGH
          identity.contextData[ATTRIBUTE_MOBILEUSER_AMR] shouldBe "mfa sc"
          identity.contextData[ATTRIBUTE_MOBILEUSER_PROFESSION_OID] shouldBe "1.2.276.0.76.4.49"
          identity.contextData[ATTRIBUTE_MOBILEUSER_ORGANIZATION] shouldBe "Praxis Musterarzt"
        }
      }

      test("reads a single-valued amr claim as one method") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_AMR to "mfa"))

          identity.contextData[ATTRIBUTE_MOBILEUSER_AMR] shouldBe "mfa"
        }
      }

      test("leaves amr and the optional claims out of the context data when the ID token omits them") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse())

          identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_AMR
          identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_PROFESSION_OID
          identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_ORGANIZATION
          identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_BIRTHDATE
        }
      }

      test("carries the display name and the consented birthdate into the context data (A_26973-03)") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_BIRTHDATE to "1987-06-05"))

          identity.contextData[ATTRIBUTE_MOBILEUSER_DISPLAY_NAME] shouldBe DISPLAY_NAME
          identity.contextData[ATTRIBUTE_MOBILEUSER_BIRTHDATE] shouldBe "1987-06-05"
        }
      }

      test("drops a birthdate that is no YYYY-MM-DD date rather than rejecting the login") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          // +10000-01-01 and -0001-01-01 pass LocalDate.parse, only the YYYY-MM-DD check catches them
          listOf("1987", "1987-13-01", "1987-02-30", "05.06.1987", " 1987-06-05", 19870605, "+10000-01-01", "-0001-01-01").forEach { birthdate ->
            val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_BIRTHDATE to birthdate))

            identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_BIRTHDATE
          }
        }
      }

      test("rejects an ID token that carries no display name") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val rejection =
              shouldThrow<IdentityBrokerException> { provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_DISPLAY_NAME to null)) }

          rejection.reasons shouldContain CLAIM_DISPLAY_NAME
        }
      }

      test("rejects an ID token whose display name is blank") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val rejection =
              shouldThrow<IdentityBrokerException> { provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_DISPLAY_NAME to "  ")) }

          rejection.reasons shouldContain CLAIM_DISPLAY_NAME
        }
      }

      test("drops an empty amr claim rather than writing a blank note") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_AMR to listOf<String>()))

          identity.contextData shouldNotContainKey ATTRIBUTE_MOBILEUSER_AMR
        }
      }

      test("rejects an ID token that carries no KVNR") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val rejection =
              shouldThrow<IdentityBrokerException> { provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_KVNR to null)) }

          rejection.reasons shouldContain CLAIM_KVNR
        }
      }

      test("rejects an ID token that carries no acr") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val rejection =
              shouldThrow<IdentityBrokerException> { provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_ACR to null)) }

          rejection.reasons shouldContain CLAIM_ACR
        }
      }

      test("rejects an ID token whose acr is blank — an unknown level is not a level") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp)

          val rejection =
              shouldThrow<IdentityBrokerException> { provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_ACR to "  ")) }

          rejection.reasons shouldContain CLAIM_ACR
        }
      }
    }

    context("user data at the user (A_26973-02)") {
      test("stores the user data of the ID token as user attributes, but not acr and amr") {
        FederationMock().use { sekIdp ->
          val identity =
              providerFor(sekIdp).getFederatedIdentity(
                  sekIdp.tokenResponse(
                      CLAIM_AMR to listOf("mfa"),
                      CLAIM_BIRTHDATE to "1987-06-05",
                      CLAIM_PROFESSION to "1.2.276.0.76.4.49",
                      CLAIM_ORGANIZATION to "Praxis Musterarzt",
                  ))
          val attributes = mutableMapOf<String, String>()

          userWith(attributes).storeUserData(identity)

          attributes shouldContainExactly
              mapOf(
                  ATTRIBUTE_MOBILEUSER_KVNR to KVNR,
                  ATTRIBUTE_MOBILEUSER_DISPLAY_NAME to DISPLAY_NAME,
                  ATTRIBUTE_MOBILEUSER_BIRTHDATE to "1987-06-05",
                  ATTRIBUTE_MOBILEUSER_PROFESSION_OID to "1.2.276.0.76.4.49",
                  ATTRIBUTE_MOBILEUSER_ORGANIZATION to "Praxis Musterarzt",
              )
        }
      }

      test("updates changed values and removes what the ID token no longer carries, e.g. a withdrawn birthdate consent") {
        FederationMock().use { sekIdp ->
          val identity = providerFor(sekIdp).getFederatedIdentity(sekIdp.tokenResponse())
          val attributes =
              mutableMapOf(
                  ATTRIBUTE_MOBILEUSER_KVNR to KVNR,
                  ATTRIBUTE_MOBILEUSER_DISPLAY_NAME to "Erika Mustermann",
                  ATTRIBUTE_MOBILEUSER_BIRTHDATE to "1987-06-05",
                  ATTRIBUTE_MOBILEUSER_PROFESSION_OID to "1.2.276.0.76.4.49",
                  ATTRIBUTE_MOBILEUSER_ORGANIZATION to "Praxis Musterarzt",
                  "unrelated" to "kept",
              )

          userWith(attributes).storeUserData(identity)

          attributes shouldContainExactly
              mapOf(ATTRIBUTE_MOBILEUSER_KVNR to KVNR, ATTRIBUTE_MOBILEUSER_DISPLAY_NAME to DISPLAY_NAME, "unrelated" to "kept")
        }
      }

      test("leaves unchanged values alone, so a repeated login does not write") {
        FederationMock().use { sekIdp ->
          val identity = providerFor(sekIdp).getFederatedIdentity(sekIdp.tokenResponse())
          val user = userWith(mutableMapOf(ATTRIBUTE_MOBILEUSER_KVNR to KVNR, ATTRIBUTE_MOBILEUSER_DISPLAY_NAME to DISPLAY_NAME))

          user.storeUserData(identity)

          verify(exactly = 0) { user.setSingleAttribute(any(), any()) }
          verify(exactly = 0) { user.removeAttribute(any()) }
        }
      }
    }

    context("integrity provider — the user data must not be stored unencrypted") {
      test("lets the login through while the integrity provider is disabled") {
        FederationMock().use { sekIdp ->
          providerFor(sekIdp, integrityProvider = integrityProvider(enabled = false, running = false)).checkIntegrityProvider().shouldBeRight()
        }
      }

      test("lets the login through once the integrity provider is running") {
        FederationMock().use { sekIdp ->
          providerFor(sekIdp, integrityProvider = integrityProvider(enabled = true, running = true)).checkIntegrityProvider().shouldBeRight()
        }
      }

      test("rejects the login with 503 while the enabled integrity provider is not running yet") {
        FederationMock().use { sekIdp ->
          val provider = providerFor(sekIdp, integrityProvider = integrityProvider(enabled = true, running = false))

          provider.checkIntegrityProvider().shouldBeLeft().statusCode shouldBe 503
        }
      }
    }

    context("nonce echo (A_29672)") {
      test("accepts an ID token echoing the nonce the client note names") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, brokerNonce = NONCE)
          val provider = providerFor(sekIdp, session)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_NONCE to NONCE))

          provider.preprocess(session, identity)

          identity.contextData[NOTE_BROKER_NONCE] shouldBe NONCE
        }
      }

      test("rejects an ID token that echoes no nonce at all") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, brokerNonce = NONCE)
          val provider = providerFor(sekIdp, session)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse())

          shouldThrow<IdentityBrokerException> { provider.preprocess(session, identity) }
        }
      }

      test("rejects an ID token echoing a nonce the client note does not name") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, brokerNonce = NONCE)
          val provider = providerFor(sekIdp, session)

          val identity = provider.getFederatedIdentity(sekIdp.tokenResponse(CLAIM_NONCE to "$NONCE-tampered"))

          val rejection = shouldThrow<ErrorResponseException> { provider.preprocess(session, identity) }

          rejection.error shouldBe "invalid_token"
          rejection.errorDescription shouldBe "invalid nonce"
          rejection.response.status shouldBe 400
        }
      }
    }

    context("inner PAR (A_29660)") {
      test("pushes the authorization request carrying the parameters the spec names") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, oidcRedirectUri = OIDC_REDIRECT_URI)
          val provider = providerFor(sekIdp, session)

          provider.createAuthorizationUrl(requestFor(session))

          val par = sekIdp.parRequest()
          par["client_id"] shouldBe CLIENT_ID
          par["state"] shouldBe OUTER_STATE
          par["redirect_uri"] shouldBe OIDC_REDIRECT_URI
          par["response_type"] shouldBe "code"
          par["scope"] shouldBe DEFAULT_SCOPE
          par["acr_values"] shouldBe ACR_HIGH
          par["code_challenge_method"] shouldBe "S256"
          par["code_challenge"].shouldNotBeNull()
          par[IDToken.NONCE].shouldNotBeNull()
        }
      }

      test("returns the authorization URL carrying the request_uri the PAR handed out") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, oidcRedirectUri = OIDC_REDIRECT_URI)
          val provider = providerFor(sekIdp, session)

          val url = provider.createAuthorizationUrl(requestFor(session)).build()

          url.toString() shouldStartWith sekIdp.authorizationEndpoint
          val query = url.query.split("&").associate { it.substringBefore('=') to it.substringAfter('=') }
          query["request_uri"] shouldBe sekIdp.parRequestUri
          query["client_id"] shouldBe CLIENT_ID
        }
      }

      test("leaves the notes behind that the callback and the token request need") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, oidcRedirectUri = OIDC_REDIRECT_URI)
          val provider = providerFor(sekIdp, session)

          provider.createAuthorizationUrl(requestFor(session))

          val authSession = session.context.authenticationSession
          val par = sekIdp.parRequest()
          // The ID token's nonce echo is checked against this note (A_29672).
          authSession.getClientNote(NOTE_BROKER_NONCE) shouldBe par[IDToken.NONCE]
          // The note stores the verifier; the PAR carried its S256 challenge.
          val verifier = authSession.getClientNote(NOTE_BROKER_CODE_VERIFIER).shouldNotBeNull()
          PkceUtils.encodeCodeChallenge(verifier, "S256") shouldBe par["code_challenge"]
          authSession.getClientNote(NOTE_BROKER_CODE_CHALLENGE_METHOD) shouldBe "S256"
          // RFC 6749 requires the token request to repeat the redirect_uri; this note carries it over.
          authSession.getClientNote(NOTE_OIDC_REDIRECT_URI) shouldBe OIDC_REDIRECT_URI
        }
      }

      test("aborts when the PAR endpoint answers with anything but 201") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, oidcRedirectUri = OIDC_REDIRECT_URI)
          val provider = providerFor(sekIdp, session)

          sekIdp.serve(FederationEndpoint.PAR, """{"error":"invalid_request"}""", status = 400)

          val rejection = shouldThrow<IdentityBrokerException> { provider.createAuthorizationUrl(requestFor(session)) }

          rejection.reasons shouldContain "HTTP 400"
        }
      }

      test("rejects an authorization request that names no idp_iss") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp, idpIss = null, oidcRedirectUri = OIDC_REDIRECT_URI)
          val provider = providerFor(sekIdp, session)

          val rejection = shouldThrow<IdentityBrokerException> { provider.createAuthorizationUrl(requestFor(session)) }

          rejection.reasons shouldContain "idp_iss"
        }
      }

      test("rejects an authorization request that names no oidc_redirect_uri") {
        FederationMock().use { sekIdp ->
          val session = sessionFor(sekIdp)
          val provider = providerFor(sekIdp, session)

          val rejection = shouldThrow<IdentityBrokerException> { provider.createAuthorizationUrl(requestFor(session)) }

          rejection.reasons shouldContain "oidc_redirect_uri"
        }
      }
    }
  }

  /** The provider under test, talking to [sekIdp] through [session]. */
  private fun providerFor(
      sekIdp: FederationMock,
      session: KeycloakSession = sessionFor(sekIdp),
      integrityProvider: IntegrityProviderService = integrityProvider(enabled = false, running = false),
  ): SekIDPIdentityProvider {
    val config =
        OIDCIdentityProviderConfig(IdentityProviderModel()).apply {
          clientId = CLIENT_ID
          defaultScope = DEFAULT_SCOPE
          // IdentityProviderModel defaults to disabled, and getFederatedIdentity refuses a disabled provider.
          isEnabled = true
        }

    // Without an mTLS config this client holds no resources, so nothing has to close it.
    return SekIDPIdentityProvider(session, config, SimpleHttp.create(session.lookupHttpClient(SEKIDP_MTLS_HTTP_CLIENT_ID)), integrityProvider, sekIdp.fedmasterUrl)
  }

  /**
   * The authentication session the provider reads and writes.
   *
   * [idpIss] carries the mock's own issuer. `null` models a client that omitted `idp_iss` on the authorization request.
   * [brokerNonce] is the `BROKER_NONCE` client note `createAuthorizationUrl` would have left behind, [oidcRedirectUri]
   * the client's `oidc_redirect_uri` request parameter.
   */
  private fun sessionFor(
      sekIdp: FederationMock,
      idpIss: String? = sekIdp.sekIdpIssuer,
      brokerNonce: String? = null,
      oidcRedirectUri: String? = null,
  ): KeycloakSession {
    val httpClientProvider =
        mockk<HttpClientProvider>().also {
          every { it.httpClient } returns httpClient
          every { it.maxConsumedResponseSize } returns HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE
        }

    // Map-backed notes: createAuthorizationUrl writes the notes the assertions (and later calls) read back.
    val notes = mutableMapOf<String, String>()
    idpIss?.let { notes[NOTE_IDP_ISS] = it }
    brokerNonce?.let { notes[NOTE_BROKER_NONCE] = it }
    oidcRedirectUri?.let { notes[NOTE_OIDC_REDIRECT_URI_PARAM] = it }

    val authSession =
        mockk<AuthenticationSessionModel>().also {
          every { it.getClientNote(any()) } answers { notes[firstArg()] }
          every { it.setClientNote(any(), any()) } answers { notes[firstArg<String>()] = secondArg() }
        }

    return mockk<KeycloakSession>().also {
      every { it.getProvider(HttpClientProvider::class.java, SEKIDP_MTLS_HTTP_CLIENT_ID) } returns httpClientProvider
      every { it.context } returns mockk<KeycloakContext>().also { context -> every { context.authenticationSession } returns authSession }
    }
  }
}

private fun integrityProvider(enabled: Boolean, running: Boolean): IntegrityProviderService =
    mockk {
      every { isIntegrityProviderEnabled() } returns enabled
      every { isIntegrityProviderRunning() } returns running
    }

/** A user whose attributes live in [attributes] — all [storeUserData] reads and writes. */
private fun userWith(attributes: MutableMap<String, String>): UserModel =
    mockk {
      every { getFirstAttribute(any()) } answers { attributes[firstArg()] }
      every { setSingleAttribute(any(), any()) } answers { attributes[firstArg<String>()] = secondArg() }
      every { removeAttribute(any()) } answers { attributes -= firstArg<String>() }
    }

/** The realm is part of the signature but untouched by the nonce check, so it stays an empty mock. */
private fun SekIDPIdentityProvider.preprocess(session: KeycloakSession, identity: BrokeredIdentityContext) =
    preprocessFederatedIdentity(session, mockk<RealmModel>(), identity)

/** The request as Keycloak's broker endpoint hands it over. The provider touches only the session and the relay state. */
private fun requestFor(session: KeycloakSession): AuthenticationRequest =
    mockk {
      every { authenticationSession } returns session.context.authenticationSession
      every { state } returns mockk { every { encoded } returns OUTER_STATE }
    }

/**
 * A token response as the SekIDP's token endpoint returns it, carrying the claims a valid login brings.
 *
 * [claims] are merged last, so a test overrides a default claim by repeating its name, or drops it by passing `null`.
 */
private fun FederationMock.tokenResponse(vararg claims: Pair<String, Any?>): String =
    JsonSerialization.writeValueAsString(
        mapOf(
            "access_token" to "mock-access-token",
            "token_type" to "Bearer",
            "id_token" to idToken(claims = mapOf(CLAIM_KVNR to KVNR, CLAIM_DISPLAY_NAME to DISPLAY_NAME, CLAIM_ACR to ACR_HIGH) + claims),
        ))

/**
 * Every message in the exception chain, joined. The base class wraps whatever [SekIDPIdentityProvider.extractIdentity]
 * throws into its own "Could not fetch attributes from userinfo endpoint", so the message that matters sits on a cause.
 */
private val Throwable.reasons: String
  get() = generateSequence(this) { it.cause }.mapNotNull { it.message }.joinToString(" | ")
