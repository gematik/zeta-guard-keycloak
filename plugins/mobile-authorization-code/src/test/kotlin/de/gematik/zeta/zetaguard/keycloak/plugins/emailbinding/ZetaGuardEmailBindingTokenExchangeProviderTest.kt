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
package de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.MOCK_MOBILE_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.mockk.CapturingSlot
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.spyk
import io.mockk.unmockkConstructor
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.HttpHeaders
import jakarta.ws.rs.core.MultivaluedHashMap
import jakarta.ws.rs.core.Response
import java.time.Duration
import java.util.stream.Stream
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException
import org.keycloak.common.ClientConnection
import org.keycloak.common.util.Time
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.events.EventBuilder
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientScopeModel
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakUriInfo
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper
import org.keycloak.protocol.oidc.TokenExchangeContext
import org.keycloak.protocol.oidc.TokenExchangeContext.Params
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.representations.AccessToken
import org.keycloak.services.CorsErrorResponseException
import org.keycloak.services.cors.Cors
import org.keycloak.services.managers.AuthenticationManager

class ZetaGuardEmailBindingTokenExchangeProviderTest : FunSpec() {
  init {
    beforeEach {
      mockkObject(OidcFlowSettings)
      every { OidcFlowSettings.isEnabled() } returns true
    }
    afterEach {
      unmockkObject(OidcFlowSettings)
      unmockkConstructor(ZetaGuardDataService::class)
      unmockkObject(OpaGateEnforcer)
      unmockkStatic(OIDCAdvancedConfigWrapper::class)
      unmockkStatic(AuthenticationManager::class)
      unmockkStatic(TokenManager::class)
      unmockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
    }

    test("supports does not claim clients when mobile flow is disabled") {
      every { OidcFlowSettings.isEnabled() } returns false
      val context = supportContext(subjectToken = bindingToken())

      ZetaGuardEmailBindingTokenExchangeProvider().supports(context) shouldBe false
      verify(exactly = 0) { anyConstructed<ZetaGuardDataService>().findClientData(any()) }
    }

    test("supports SEK_IDP clients with email-verify subject tokens") {
      val context = supportContext(subjectToken = bindingToken())

      ZetaGuardEmailBindingTokenExchangeProvider().supports(context) shouldBe true
    }

    test("supports rejects non SEK_IDP clients") {
      val clientData = mobileClientData().apply { clientAuthMethod = ClientAuthMethod.SMC_B }
      val context = supportContext(subjectToken = bindingToken(), clientData = clientData)

      ZetaGuardEmailBindingTokenExchangeProvider().supports(context) shouldBe false
      context.unsupportedReason shouldBe "Email-binding token exchange supports SEK_IDP clients only"
    }

    test("supports rejects subject tokens that only carry zeta:email-binding") {
      val context = supportContext(subjectToken = unsignedToken(SCOPE_EMAIL_BINDING))

      ZetaGuardEmailBindingTokenExchangeProvider().supports(context) shouldBe false
      context.unsupportedReason shouldBe "Email-binding token exchange supports email-binding subject tokens only"
    }

    test("supports rejects subject tokens without complete-registration scope") {
      val context = supportContext(subjectToken = unsignedToken("openid profile"))

      ZetaGuardEmailBindingTokenExchangeProvider().supports(context) shouldBe false
      context.unsupportedReason shouldBe "Email-binding token exchange supports email-binding subject tokens only"
    }

    test("tokenExchange rejects subject token issued for a different client") {
      val ex =
          shouldThrow<CorsErrorResponseException> {
            exchange(
                token = accessToken(issuedFor = "other-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
                clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
            )
          }
      ex.message shouldBe OAuthErrorException.INVALID_GRANT
      ex.errorDescription shouldBe "Subject token was not issued to this client"
    }

    test("tokenExchange rejects subject token without zeta:email-verify even if email-binding is present") {
      val ex =
          shouldThrow<CorsErrorResponseException> {
            exchange(
                token =
                    accessToken(
                        issuedFor = "mobile-client",
                        scope = "$SCOPE_EMAIL_BINDING openid",
                    ),
                clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
            )
          }
      ex.message shouldBe OAuthErrorException.INVALID_GRANT
      ex.errorDescription shouldBe "Subject token is not an email-binding token"
    }

    test("tokenExchange rejects when registration is not CONFIRMED") {
      val ex =
          shouldThrow<CorsErrorResponseException> {
            exchange(
                token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
                clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING),
            )
          }
      ex.message shouldBe OAuthErrorException.INVALID_GRANT
      ex.errorDescription shouldBe "Email binding not complete"
      verify(exactly = 0) { OpaGateEnforcer.enforce(any(), any(), any()) }
    }

    test("tokenExchange restores authorize scopes from the client-session note and consults OPA when CONFIRMED") {
      val openid = clientScope("openid")
      val profile = clientScope("profile")
      val emailBinding = clientScope(SCOPE_EMAIL_BINDING)
      val emailVerify = clientScope(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)

      var restrictedScopes: Set<String>? = null
      val ok = Response.ok(mapOf("token_type" to "Bearer")).build()
      val opaInput = slot<OpaGateInput>()
      val provider =
          exchange(
              token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
              clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
              originalScopeNote = "openid profile $SCOPE_EMAIL_BINDING $SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION",
              audienceNote = "https://fachdienst.example",
              requestedScopes = Stream.of(openid, profile, emailBinding, emailVerify),
              exchangeResponse = ok,
              onRestrictedScopes = { restrictedScopes = it },
              opaInputSlot = opaInput,
          )

      provider shouldNotBe null
      restoredScopeParam(provider!!) shouldBe
          "openid profile $SCOPE_EMAIL_BINDING $SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION"
      restrictedScopes shouldBe setOf("openid", "profile")
      opaInput.captured.grantType shouldBe OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
      opaInput.captured.scopes shouldBe listOf("openid", "profile", SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)
      opaInput.captured.audiences shouldBe listOf("https://fachdienst.example")
      opaInput.captured.clientId shouldBe "mobile-client-uuid"
      opaInput.captured.clientPlatform shouldBe "apple"
      opaInput.captured.authenticationMethodsReferences shouldBe listOf("mfa")
      opaInput.captured.authenticationContextClassReference shouldBe "abc"
      opaInput.captured.userIdentifier shouldBe "X110123456"
      opaInput.captured.userProfessionOid shouldBe "1.2.276.0.76.4.49"
    }

    test("OPA deny aborts full token issuance on email-binding exchange") {
      shouldThrow<WebApplicationException> {
        exchange(
            token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
            clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
            originalScopeNote = "openid profile $SCOPE_EMAIL_BINDING $SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION",
            audienceNote = "https://fachdienst.example",
            opaOutcome = OpaGateEnforcer.Outcome.Deny(KeycloakError("access_denied", "policy_denied", Response.Status.FORBIDDEN)),
            expectLastIpUpdate = false,
        )
      }
    }

    test("OPA allow stores access and refresh TTLs on the user session") {
      val ok = Response.ok(mapOf("token_type" to "Bearer")).build()
      val ttlNote = slot<String>()
      exchange(
          token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
          clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
          originalScopeNote = "openid profile",
          audienceNote = "https://fachdienst.example",
          exchangeResponse = ok,
          onRestrictedScopes = {},
          opaOutcome = OpaGateEnforcer.Outcome.Allow(accessTokenTtl = 120, refreshTokenTtl = 600),
          ttlNoteSlot = ttlNote,
      )

      val ttls = ttlNote.captured.toObject<OpaSessionContext>()
      ttls.accessTokenTTL shouldBe Duration.ofSeconds(120)
      ttls.refreshTokenTTL shouldBe Duration.ofSeconds(600)
      ttls.scopes shouldBe listOf("openid", "profile")
      ttls.audiences shouldBe listOf("https://fachdienst.example")
    }

    test("OPA allow records last client IP only after successful issuance") {
      val ok = Response.ok(mapOf("token_type" to "Bearer")).build()
      exchange(
          token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
          clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
          originalScopeNote = "openid profile",
          audienceNote = "https://fachdienst.example",
          exchangeResponse = ok,
          onRestrictedScopes = {},
          expectLastIpUpdate = true,
      )
    }

    test("OPA allow does not record last client IP when token issuance fails") {
      exchange(
          token = accessToken(issuedFor = "mobile-client", scope = SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION),
          clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED),
          originalScopeNote = "openid profile",
          audienceNote = "https://fachdienst.example",
          exchangeResponse = Response.serverError().build(),
          onRestrictedScopes = {},
          expectSuccess = false,
          expectLastIpUpdate = false,
      )
    }
  }

  private fun supportContext(
      subjectToken: String,
      clientData: ZetaGuardClientData = mobileClientData(),
  ): TokenExchangeContext {
    mockkConstructor(ZetaGuardDataService::class)
    mockkStatic(OIDCAdvancedConfigWrapper::class)

    val client = mockk<ClientModel>(relaxed = true)
    every { client.clientId } returns "mobile-client"
    every { anyConstructed<ZetaGuardDataService>().findClientData("mobile-client") } returns clientData

    val wrapper = mockk<OIDCAdvancedConfigWrapper>()
    every { wrapper.isStandardTokenExchangeEnabled } returns true
    every { OIDCAdvancedConfigWrapper.fromClientModel(client) } returns wrapper

    val params = mockk<Params>()
    every { params.subjectToken } returns subjectToken
    every { params.subjectTokenType } returns OAuth2Constants.ACCESS_TOKEN_TYPE

    val context = mockk<TokenExchangeContext>(relaxed = true)
    every { context.session } returns mockk(relaxed = true)
    every { context.client } returns client
    every { context.params } returns params
    every { context.formParams } returns MultivaluedHashMap()
    every { context.unsupportedReason = any() } answers { every { context.unsupportedReason } returns firstArg() }
    return context
  }

  private fun exchange(
      token: AccessToken,
      clientData: ZetaGuardClientData,
      originalScopeNote: String = "openid profile",
      audienceNote: String? = null,
      requestedScopes: Stream<ClientScopeModel> = Stream.empty(),
      exchangeResponse: Response = Response.ok().build(),
      onRestrictedScopes: ((Set<String>) -> Unit)? = null,
      opaOutcome: OpaGateEnforcer.Outcome = OpaGateEnforcer.Outcome.Allow(),
      opaInputSlot: CapturingSlot<OpaGateInput>? = null,
      ttlNoteSlot: CapturingSlot<String>? = null,
      expectSuccess: Boolean = true,
      expectLastIpUpdate: Boolean? = null,
  ): ZetaGuardEmailBindingTokenExchangeProvider? {
    mockkConstructor(ZetaGuardDataService::class)
    mockkStatic(OIDCAdvancedConfigWrapper::class)
    mockkStatic(AuthenticationManager::class)
    mockkStatic(TokenManager::class)
    mockkObject(OpaGateEnforcer)

    val client = mockk<ClientModel>(relaxed = true)
    every { client.clientId } returns "mobile-client"
    every { client.id } returns "mobile-client-uuid"
    every { client.getAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW) } returns MOCK_MOBILE_CLIENT_STATEMENT
    every { client.attributes } returns
        mapOf(ATTRIBUTE_CLIENT_STATEMENT_RAW to MOCK_MOBILE_CLIENT_STATEMENT, ATTRIBUTE_LAST_CLIENT_IP to "10.0.0.2")
    every { anyConstructed<ZetaGuardDataService>().findClientData("mobile-client") } returns clientData

    val wrapper = mockk<OIDCAdvancedConfigWrapper>()
    every { wrapper.isStandardTokenExchangeEnabled } returns true
    every { OIDCAdvancedConfigWrapper.fromClientModel(client) } returns wrapper

    val user = mockk<UserModel>(relaxed = true)
    every { user.username } returns "alice"

    val clientSession = mockk<AuthenticatedClientSessionModel>(relaxed = true)
    every { clientSession.getNote(OAuth2Constants.SCOPE) } returns originalScopeNote
    every { clientSession.getNote(OAuth2Constants.AUDIENCE) } returns audienceNote

    val userSession = mockk<UserSessionModel>(relaxed = true)
    every { userSession.getAuthenticatedClientSessionByClient("mobile-client-uuid") } returns clientSession
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns "X110123456"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_PROFESSION_OID) } returns "1.2.276.0.76.4.49"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_AMR) } returns "mfa"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_ACR) } returns "abc"
    if (ttlNoteSlot != null) {
      every { userSession.setNote(ATTRIBUTE_MOBILE_OPA_CONTEXT, capture(ttlNoteSlot)) } returns Unit
    }

    val authResult = mockk<AuthenticationManager.AuthResult>()
    every { authResult.token() } returns token
    every { authResult.user() } returns user
    every { authResult.session() } returns userSession

    val uriInfo = mockk<KeycloakUriInfo>(relaxed = true)
    val keycloakContext = mockk<KeycloakContext>(relaxed = true)
    every { keycloakContext.uri } returns uriInfo
    every { keycloakContext.connection.remoteAddr } returns "10.0.0.1"
    every { keycloakContext.requestHeaders } returns null

    val session = mockk<KeycloakSession>(relaxed = true)
    every { session.context } returns keycloakContext
    val httpClientProvider = mockk<HttpClientProvider>()
    every { httpClientProvider.httpClient } returns mockk(relaxed = true)
    every { session.getProvider(HttpClientProvider::class.java) } returns httpClientProvider

    every { TokenManager.getRequestedClientScopes(any(), any(), any(), any()) } returns requestedScopes

    every {
      AuthenticationManager.verifyIdentityToken(
          any(), any(), any(), any(), any(), any(), any(), any(), any(), any(), any())
    } returns authResult

    if (opaInputSlot != null) {
      every { OpaGateEnforcer.enforce(any(), capture(opaInputSlot), any()) } returns opaOutcome
    } else {
      every { OpaGateEnforcer.enforce(any(), any(), any()) } returns opaOutcome
    }

    val params = mockk<Params>(relaxed = true)
    every { params.subjectToken } returns "subject-token"
    every { params.subjectTokenType } returns OAuth2Constants.ACCESS_TOKEN_TYPE
    every { params.requestedTokenType } returns OAuth2Constants.ACCESS_TOKEN_TYPE

    val event = mockk<EventBuilder>(relaxed = true)

    val context = mockk<TokenExchangeContext>(relaxed = true)
    every { context.session } returns session
    every { context.client } returns client
    every { context.realm } returns mockk<RealmModel>(relaxed = true)
    every { context.params } returns params
    every { context.formParams } returns MultivaluedHashMap()
    every { context.event } returns event
    every { context.cors } returns mockk<Cors>(relaxed = true)
    every { context.clientConnection } returns mockk<ClientConnection>(relaxed = true)
    every { context.headers } returns mockk<HttpHeaders>(relaxed = true)
    every { context.tokenManager } returns mockk<TokenManager>(relaxed = true)
    every { context.clientAuthAttributes } returns emptyMap()
    every { context.restrictedScopes = any() } answers
        {
          @Suppress("UNCHECKED_CAST")
          onRestrictedScopes?.invoke(firstArg() as Set<String>)
        }

    val provider = spyk(ZetaGuardEmailBindingTokenExchangeProvider(), recordPrivateCalls = true)
    every {
      provider["exchangeClientToClient"](any<UserModel>(), any<UserSessionModel>(), any<AccessToken>(), any<Boolean>())
    } returns exchangeResponse

    var thrown: Throwable? = null
    val response =
        try {
          provider.exchange(context)
        } catch (e: Throwable) {
          thrown = e
          null
        }
    when (expectLastIpUpdate) {
      true -> verify { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, "10.0.0.1") }
      false -> verify(exactly = 0) { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, any()) }
      null -> {}
    }
    if (thrown != null) throw thrown
    if (onRestrictedScopes != null) {
      if (expectSuccess) {
        response!!.status shouldBe Response.Status.OK.statusCode
      }
      return provider
    }
    return null
  }

  private fun mobileClientData(
      status: ClientRegistrationStatus = ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
  ): ZetaGuardClientData {
    val now = currentTime()
    return ZetaGuardClientData("mobile-client", now, now).apply {
      clientAuthMethod = ClientAuthMethod.SEK_IDP
      registrationStatus = status
    }
  }

  private fun bindingToken(): String = unsignedToken(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)

  private fun unsignedToken(scope: String): String {
    val now = Time.currentTime().toLong()
    val token =
        AccessToken().apply {
          this.scope = scope
          issuedFor = "mobile-client"
          exp(now + 300)
          iat(now)
        }
    return JWSBuilder().jsonContent(token).none()
  }

  private fun accessToken(issuedFor: String, scope: String): AccessToken =
      AccessToken().apply {
        this.issuedFor = issuedFor
        this.scope = scope
        this.sessionId = "session-1"
      }

  private fun clientScope(name: String): ClientScopeModel {
    val scope = mockk<ClientScopeModel>()
    every { scope.name } returns name
    return scope
  }

  private fun restoredScopeParam(provider: ZetaGuardEmailBindingTokenExchangeProvider): String? {
    val field = ZetaGuardEmailBindingTokenExchangeProvider::class.java.getDeclaredField("restoredScopeParam")
    field.isAccessible = true
    return field.get(provider) as String?
  }
}
