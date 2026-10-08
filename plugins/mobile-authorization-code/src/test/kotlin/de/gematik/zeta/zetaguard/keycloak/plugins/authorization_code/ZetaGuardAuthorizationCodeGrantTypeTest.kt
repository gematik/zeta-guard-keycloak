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
package de.gematik.zeta.zetaguard.keycloak.plugins.authorization_code

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_COLLECT_EMAIL
import de.gematik.zeta.zetaguard.keycloak.commons.server.BINDING_MODE_VERIFY_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_BINDING_MODE
import de.gematik.zeta.zetaguard.keycloak.commons.server.RESPONSE_MEMBER_EMAIL_HINT
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.MOCK_MOBILE_CLIENT_STATEMENT
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpMailer
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailOtpService
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.withTokenScopesReducedTo
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkObject
import io.mockk.unmockkStatic
import io.mockk.verify
import jakarta.persistence.EntityManager
import jakarta.ws.rs.WebApplicationException
import jakarta.ws.rs.core.MultivaluedHashMap
import jakarta.ws.rs.core.Response
import java.time.Duration
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException.UNSUPPORTED_GRANT_TYPE
import org.keycloak.common.util.Time
import org.keycloak.representations.idm.OAuth2ErrorRepresentation
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.events.EventBuilder
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.protocol.oidc.grants.OAuth2GrantType
import org.keycloak.protocol.oidc.grants.OAuth2GrantTypeBase
import org.keycloak.protocol.oidc.encode.AccessTokenContext
import org.keycloak.protocol.oidc.encode.TokenContextEncoderProvider
import org.keycloak.representations.AccessToken
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.services.cors.Cors

class ZetaGuardAuthorizationCodeGrantTypeTest : FunSpec() {
  init {
    beforeEach {
      mockkObject(OidcFlowSettings)
      every { OidcFlowSettings.isEnabled() } returns true
    }
    afterEach {
      unmockkObject(OidcFlowSettings)
      unmockkObject(EmailOtpService)
      unmockkObject(EmailOtpMailer)
      unmockkObject(OpaGateEnforcer)
      unmockkStatic(Time::class)
      unmockkStatic("de.gematik.zeta.zetaguard.keycloak.commons.server.EncodingUtilKt")
      unmockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EmailBindingScopesKt")
    }

    test("useRefreshToken is disabled while email confirmation is required") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      invokeUseRefreshToken(grant) shouldBe false
    }

    test("addCustomTokenResponseClaims asks to collect email when user has no verified email") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val user = mockk<UserModel>()
      every { user.email } returns null
      every { user.isEmailVerified } returns false
      val response = AccessTokenResponse()

      invokeAddCustomTokenResponseClaims(grant, response, clientSessionContext(user))

      response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] shouldBe BINDING_MODE_COLLECT_EMAIL
      clientData.registrationStatus shouldBe ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
    }

    test("addCustomTokenResponseClaims issues OTP and moves registration to OTP_PENDING for verified email") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val session = mockk<KeycloakSession>(relaxed = true)
      val client = mockk<ClientModel>()
      every { client.clientId } returns "mobile-client"
      setField(grant, OAuth2GrantTypeBase::class.java, "session", session)
      setField(grant, OAuth2GrantTypeBase::class.java, "client", client)

      val user = mockk<UserModel>()
      every { user.email } returns "alice@example.de"
      every { user.isEmailVerified } returns true

      mockkObject(EmailOtpService)
      mockkObject(EmailOtpMailer)
      every { EmailOtpService.issue(session, "mobile-client") } returns "123456"
      justRun { EmailOtpMailer.send(session, "alice@example.de", "123456") }

      val response = AccessTokenResponse()
      invokeAddCustomTokenResponseClaims(grant, response, clientSessionContext(user))

      response.otherClaims[RESPONSE_MEMBER_BINDING_MODE] shouldBe BINDING_MODE_VERIFY_OTP
      response.otherClaims[RESPONSE_MEMBER_EMAIL_HINT] shouldBe "a*@e*.de"
      clientData.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
      verify { EmailOtpMailer.send(session, "alice@example.de", "123456") }
    }

    test("process for unconfirmed SEK_IDP disables refresh tokens") {
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientConfig = mockk<OIDCAdvancedConfigWrapper>(relaxed = true)
      every { clientConfig.isUseRefreshToken } returns true

      runCatching { grant.process(grantContext(clientData, clientConfig)) }

      invokeUseRefreshToken(grant) shouldBe false
    }

    test("process for CONFIRMED SEK_IDP keeps the client refresh-token setting") {
      val clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientConfig = mockk<OIDCAdvancedConfigWrapper>(relaxed = true)
      every { clientConfig.isUseRefreshToken } returns true

      runCatching { grant.process(grantContext(clientData, clientConfig)) }

      invokeUseRefreshToken(grant) shouldBe true
    }

    test("createTokenResponseBuilder reduces scopes and shortens TTL when email confirmation is required") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EmailBindingScopesKt")
      mockkStatic(Time::class)
      every { Time.currentTime() } returns 1_700_000_000

      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val user = mockk<UserModel>()
      every { user.email } returns null
      every { user.isEmailVerified } returns false
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)
      val reducedCtx = mockk<ClientSessionContext>(relaxed = true)
      val scopeSlot = slot<Set<String>>()
      every { sourceCtx.withTokenScopesReducedTo(any(), capture(scopeSlot)) } returns reducedCtx

      val accessToken = AccessToken()
      val builder = prepareBuilder(grant, accessToken, expectedCtx = reducedCtx)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      scopeSlot.captured shouldBe setOf(SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)
      accessToken.exp shouldBe 1_700_000_300L
      verify { sourceCtx.withTokenScopesReducedTo(any(), any()) }
    }

    test("createTokenResponseBuilder only keeps zeta:email-verify when user already has a verified email") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EmailBindingScopesKt")
      mockkStatic(Time::class)
      every { Time.currentTime() } returns 1_700_000_000

      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.OTP_PENDING)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val user = mockk<UserModel>()
      every { user.email } returns "alice@example.de"
      every { user.isEmailVerified } returns true
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)
      val reducedCtx = mockk<ClientSessionContext>(relaxed = true)
      val scopeSlot = slot<Set<String>>()
      every { sourceCtx.withTokenScopesReducedTo(any(), capture(scopeSlot)) } returns reducedCtx

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = reducedCtx)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      scopeSlot.captured shouldBe setOf(SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)
      accessToken.exp shouldBe 1_700_000_300L
    }

    test("createTokenResponseBuilder keeps requested scopes for CONFIRMED clients") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken().apply { exp(9_999_999_999L) }
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      stubOpaAllow(grant, userSession, sourceCtx)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      accessToken.exp shouldBe 9_999_999_999L
    }

    test("OPA gate receives all token-exchange params for CONFIRMED clients") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      val inputSlot = stubOpaAllow(grant, userSession, sourceCtx)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      val input = inputSlot.captured
      input.grantType shouldBe OAuth2Constants.AUTHORIZATION_CODE
      input.clientId shouldBe "client-internal-id"
      input.clientPlatform shouldBe "apple"
      input.clientProductID shouldBe "demo_client"
      input.clientProductVersion shouldBe "0.1.0"
      input.postureType shouldBe "apple"
      input.scopes shouldBe listOf("openid", "email")
      input.audiences shouldBe listOf("https://fachdienst.example")
      input.authenticationMethodsReferences shouldBe listOf("mfa")
      input.authenticationContextClassReference shouldBe "abc"
      input.ipAddress shouldBe "10.0.0.1"
      input.previousIpAddress shouldBe "10.0.0.2"
      input.userIdentifier shouldBe "X110123456"
      input.userProfessionOid shouldBe "1.2.276.0.76.4.49"
    }

    test("OPA deny aborts token issuance for CONFIRMED clients") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      stubOpa(
          grant,
          userSession,
          sourceCtx,
          OpaGateEnforcer.Outcome.Deny(KeycloakError("access_denied", "policy_denied", Response.Status.FORBIDDEN)),
      )

      shouldThrow<WebApplicationException> { invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx) }
    }

    test("OPA allow stores access and refresh TTLs on the user session") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken().apply { exp(9_999_999_999L) }
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      stubOpa(grant, userSession, sourceCtx, OpaGateEnforcer.Outcome.Allow(accessTokenTtl = 111, refreshTokenTtl = 222))

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      val note = slot<String>()
      verify { userSession.setNote(ATTRIBUTE_MOBILE_OPA_CONTEXT, capture(note)) }
      val ttls = note.captured.toObject<OpaSessionContext>()
      ttls.accessTokenTTL shouldBe Duration.ofSeconds(111)
      ttls.refreshTokenTTL shouldBe Duration.ofSeconds(222)
      ttls.scopes shouldBe listOf("openid", "email")
      ttls.audiences shouldBe listOf("https://fachdienst.example")
      ttls.clientId shouldBe "client-internal-id"
      ttls.userIdentifier shouldBe "X110123456"
      accessToken.exp shouldBe 9_999_999_999L
      val client = getField<ClientModel>(grant, OAuth2GrantTypeBase::class.java, "client")
      verify(exactly = 0) { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, any()) }
    }

    test("OPA allow with partial TTLs does not update the session note") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken().apply { exp(9_999_999_999L) }
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      stubOpa(grant, userSession, sourceCtx, OpaGateEnforcer.Outcome.Allow(accessTokenTtl = 111, refreshTokenTtl = null))

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      verify(exactly = 0) { userSession.setNote(ATTRIBUTE_MOBILE_OPA_CONTEXT, any()) }
      accessToken.exp shouldBe 9_999_999_999L
    }

    test("reduced email-binding token is issued without consulting OPA") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EmailBindingScopesKt")
      mockkStatic(Time::class)
      mockkObject(OpaGateEnforcer)
      every { Time.currentTime() } returns 1_700_000_000

      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val user = mockk<UserModel>()
      every { user.email } returns null
      every { user.isEmailVerified } returns false
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)
      val reducedCtx = mockk<ClientSessionContext>(relaxed = true)
      every { sourceCtx.withTokenScopesReducedTo(any(), any()) } returns reducedCtx

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = reducedCtx)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      verify(exactly = 0) { OpaGateEnforcer.enforce(any(), any(), any()) }
    }

    test("stores requested audience on the client session when email confirmation is required") {
      mockkStatic("de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding.EmailBindingScopesKt")
      mockkStatic(Time::class)
      every { Time.currentTime() } returns 1_700_000_000

      val grant = ZetaGuardAuthorizationCodeGrantType()
      val clientData = mobileClientData(ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED)
      setIssuance(grant, emailConfirmationRequired(clientData))

      val user = mockk<UserModel>()
      every { user.email } returns null
      every { user.isEmailVerified } returns false
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val clientSession = mockk<AuthenticatedClientSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)
      val reducedCtx = mockk<ClientSessionContext>(relaxed = true)
      every { sourceCtx.clientSession } returns clientSession
      every { sourceCtx.withTokenScopesReducedTo(any(), any()) } returns reducedCtx

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = reducedCtx)
      val formParams = MultivaluedHashMap<String, String>()
      formParams.putSingle(OAuth2Constants.AUDIENCE, "requiredFDaud")
      setField(grant, OAuth2GrantTypeBase::class.java, "formParams", formParams)

      invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx)

      verify { clientSession.setNote(OAuth2Constants.AUDIENCE, "requiredFDaud") }
    }

    test("OPA Skip aborts token issuance for CONFIRMED clients") {
      val grant = ZetaGuardAuthorizationCodeGrantType()
      setIssuance(grant, fullIssuance())

      val user = mockk<UserModel>(relaxed = true)
      val userSession = mockk<UserSessionModel>(relaxed = true)
      val sourceCtx = mockk<ClientSessionContext>(relaxed = true)

      val accessToken = AccessToken()
      prepareBuilder(grant, accessToken, expectedCtx = sourceCtx, useRefreshToken = true)
      stubOpa(grant, userSession, sourceCtx, OpaGateEnforcer.Outcome.Skip)
      val cors = getField<Cors>(grant, OAuth2GrantTypeBase::class.java, "cors")
      every { cors.add(any<Response.ResponseBuilder>()) } answers { firstArg<Response.ResponseBuilder>().build() }

      val ex = shouldThrow<WebApplicationException> { invokeCreateTokenResponseBuilder(grant, user, userSession, sourceCtx) }
      ex.response.status shouldBe Response.Status.BAD_REQUEST.statusCode
      val error = ex.response.entity as OAuth2ErrorRepresentation
      error.error shouldBe UNSUPPORTED_GRANT_TYPE
      error.errorDescription shouldBe "Unsupported grant type"
    }

    test("process skips client-data lookup outside the zeta-guard realm") {
      val clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val context = grantContext(clientData, realmName = "master")
      val entityManager = context.session.getProvider(JpaConnectionProvider::class.java).entityManager

      runCatching { grant.process(context) }

      verify(exactly = 0) { entityManager.find(ZetaGuardClientData::class.java, any()) }
    }

    test("process skips client-data lookup when mobile flow is disabled") {
      every { OidcFlowSettings.isEnabled() } returns false
      val clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val context = grantContext(clientData)
      val entityManager = context.session.getProvider(JpaConnectionProvider::class.java).entityManager

      runCatching { grant.process(context) }

      verify(exactly = 0) { entityManager.find(ZetaGuardClientData::class.java, any()) }
    }

    test("process looks up client data from ZETA_CLIENT_DATA even without a client attribute") {
      val clientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)
      val grant = ZetaGuardAuthorizationCodeGrantType()
      val context = grantContext(clientData)
      val entityManager = context.session.getProvider(JpaConnectionProvider::class.java).entityManager

      runCatching { grant.process(context) }

      verify { entityManager.find(ZetaGuardClientData::class.java, "mobile-client") }
    }

  }

  private fun prepareBuilder(
      grant: ZetaGuardAuthorizationCodeGrantType,
      accessToken: AccessToken,
      expectedCtx: ClientSessionContext,
      useRefreshToken: Boolean = false,
  ): TokenManager.AccessTokenResponseBuilder {
    val session = mockk<KeycloakSession>(relaxed = true)
    val realm = mockk<RealmModel>(relaxed = true)
    val client = mockk<ClientModel>(relaxed = true)
    every { client.clientId } returns "mobile-client"
    val event = mockk<EventBuilder>(relaxed = true)
    val clientConfig = mockk<OIDCAdvancedConfigWrapper>(relaxed = true)
    every { clientConfig.isUseRefreshToken } returns useRefreshToken
    every { clientConfig.isUseMtlsHokToken } returns false

    val context = mockk<OAuth2GrantType.Context>(relaxed = true)
    every { context.grantType } returns OAuth2Constants.AUTHORIZATION_CODE

    val tokenManager = mockk<TokenManager>()
    every {
      tokenManager.createClientAccessToken(session, realm, client, any(), any(), expectedCtx, any())
    } returns accessToken

    val builder = mockk<TokenManager.AccessTokenResponseBuilder>(relaxed = true)
    every { builder.accessToken } returns accessToken
    every { builder.accessToken(any()) } returns builder
    every { tokenManager.responseBuilder(realm, client, event, session, any(), expectedCtx) } returns builder

    if (!useRefreshToken) {
      val encoder = mockk<TokenContextEncoderProvider>()
      val tokenContext = mockk<AccessTokenContext>()
      every { tokenContext.sessionType } returns AccessTokenContext.SessionType.ONLINE
      every { encoder.getTokenContextFromTokenId(any()) } returns tokenContext
      every { session.getProvider(TokenContextEncoderProvider::class.java) } returns encoder
    }

    justRun { expectedCtx.setAttribute(any(), any()) }

    setField(grant, OAuth2GrantTypeBase::class.java, "session", session)
    setField(grant, OAuth2GrantTypeBase::class.java, "realm", realm)
    setField(grant, OAuth2GrantTypeBase::class.java, "client", client)
    setField(grant, OAuth2GrantTypeBase::class.java, "event", event)
    setField(grant, OAuth2GrantTypeBase::class.java, "tokenManager", tokenManager)
    setField(grant, OAuth2GrantTypeBase::class.java, "clientConfig", clientConfig)
    setField(grant, OAuth2GrantTypeBase::class.java, "formParams", MultivaluedHashMap<String, String>())
    setField(grant, OAuth2GrantTypeBase::class.java, "context", context)
    setField(grant, OAuth2GrantTypeBase::class.java, "cors", mockk<Cors>(relaxed = true))
    return builder
  }

  private fun stubOpaAllow(
      grant: ZetaGuardAuthorizationCodeGrantType,
      userSession: UserSessionModel,
      clientSessionCtx: ClientSessionContext,
  ) = stubOpa(grant, userSession, clientSessionCtx, OpaGateEnforcer.Outcome.Allow())

  private fun stubOpa(
      grant: ZetaGuardAuthorizationCodeGrantType,
      userSession: UserSessionModel,
      clientSessionCtx: ClientSessionContext,
      outcome: OpaGateEnforcer.Outcome,
  ): io.mockk.CapturingSlot<OpaGateInput> {
    val session = getField<KeycloakSession>(grant, OAuth2GrantTypeBase::class.java, "session")
    val client = getField<ClientModel>(grant, OAuth2GrantTypeBase::class.java, "client")

    val httpClientProvider = mockk<org.keycloak.connections.httpclient.HttpClientProvider>()
    every { httpClientProvider.httpClient } returns mockk(relaxed = true)
    every { session.getProvider(org.keycloak.connections.httpclient.HttpClientProvider::class.java) } returns httpClientProvider

    every { client.id } returns "client-internal-id"
    every { client.clientId } returns "mobile-client"
    every { client.getAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW) } returns MOCK_MOBILE_CLIENT_STATEMENT
    every { client.attributes } returns
        mapOf(ATTRIBUTE_CLIENT_STATEMENT_RAW to MOCK_MOBILE_CLIENT_STATEMENT, ATTRIBUTE_LAST_CLIENT_IP to "10.0.0.2")
    justRun { client.setAttribute(ATTRIBUTE_LAST_CLIENT_IP, any()) }

    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) } returns "X110123456"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_PROFESSION_OID) } returns "1.2.276.0.76.4.49"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_AMR) } returns "mfa"
    every { userSession.getNote(ATTRIBUTE_MOBILEUSER_ACR) } returns "abc"

    val clientSession = mockk<AuthenticatedClientSessionModel>(relaxed = true)
    every { clientSession.getNote(OAuth2Constants.SCOPE) } returns "openid email"
    every { clientSessionCtx.clientSession } returns clientSession

    val formParams = MultivaluedHashMap<String, String>()
    formParams.putSingle(OAuth2Constants.AUDIENCE, "https://fachdienst.example")
    setField(grant, OAuth2GrantTypeBase::class.java, "formParams", formParams)

    val kcContext = session.context
    every { kcContext.connection.remoteAddr } returns "10.0.0.1"
    every { kcContext.requestHeaders } returns null

    mockkObject(OpaGateEnforcer)
    val input = slot<OpaGateInput>()
    every { OpaGateEnforcer.enforce(any(), capture(input), any()) } returns outcome
    return input
  }

  private fun <T> getField(target: Any, type: Class<*>, name: String): T {
    val field = type.getDeclaredField(name)
    field.isAccessible = true
    @Suppress("UNCHECKED_CAST")
    return field.get(target) as T
  }

  private fun grantContext(
      clientData: ZetaGuardClientData,
      clientConfig: OIDCAdvancedConfigWrapper = mockk(relaxed = true),
      realmName: String = ZETA_REALM,
  ): OAuth2GrantType.Context {
    val entityManager = mockk<EntityManager>()
    every { entityManager.find(ZetaGuardClientData::class.java, "mobile-client") } returns clientData

    val jpa = mockk<JpaConnectionProvider>()
    every { jpa.entityManager } returns entityManager

    val session = mockk<KeycloakSession>(relaxed = true)
    every { session.getProvider(JpaConnectionProvider::class.java) } returns jpa

    val realm = mockk<RealmModel>(relaxed = true)
    every { realm.name } returns realmName

    val client = mockk<ClientModel>(relaxed = true)
    every { client.clientId } returns "mobile-client"
    every { client.realm } returns realm

    val context = mockk<OAuth2GrantType.Context>(relaxed = true)
    every { context.session } returns session
    every { context.client } returns client
    every { context.realm } returns realm
    every { context.clientConfig } returns clientConfig
    every { context.clientConnection } returns mockk(relaxed = true)
    every { context.clientAuthAttributes } returns emptyMap()
    every { context.request } returns mockk(relaxed = true)
    every { context.response } returns mockk(relaxed = true)
    every { context.headers } returns mockk(relaxed = true)
    every { context.formParams } returns mockk(relaxed = true)
    every { context.event } returns mockk(relaxed = true)
    every { context.cors } returns mockk(relaxed = true)
    every { context.tokenManager } returns mockk<TokenManager>(relaxed = true)
    return context
  }

  private fun clientSessionContext(user: UserModel): ClientSessionContext {
    val userSession = mockk<UserSessionModel>()
    every { userSession.user } returns user
    val clientSession = mockk<AuthenticatedClientSessionModel>()
    every { clientSession.userSession } returns userSession
    val ctx = mockk<ClientSessionContext>()
    every { ctx.clientSession } returns clientSession
    return ctx
  }

  private fun mobileClientData(status: ClientRegistrationStatus): ZetaGuardClientData {
    val now = currentTime()
    return ZetaGuardClientData("mobile-client", now, now).apply {
      clientAuthMethod = ClientAuthMethod.SEK_IDP
      registrationStatus = status
    }
  }

  private fun emailConfirmationRequired(clientData: ZetaGuardClientData): Any {
    val clazz =
        Class.forName(
            "de.gematik.zeta.zetaguard.keycloak.plugins.authorization_code.Issuance\$EmailConfirmationRequired")
    return clazz.getDeclaredConstructor(ZetaGuardClientData::class.java).newInstance(clientData)
  }

  private fun fullIssuance(clientData: ZetaGuardClientData = mobileClientData(ClientRegistrationStatus.CONFIRMED)): Any {
    val clazz = Class.forName("de.gematik.zeta.zetaguard.keycloak.plugins.authorization_code.Issuance\$Full")
    return clazz.getDeclaredConstructor(ZetaGuardClientData::class.java).newInstance(clientData)
  }

  private fun setIssuance(grant: ZetaGuardAuthorizationCodeGrantType, issuance: Any) {
    setField(grant, ZetaGuardAuthorizationCodeGrantType::class.java, "issuance", issuance)
  }

  private fun invokeUseRefreshToken(grant: ZetaGuardAuthorizationCodeGrantType): Boolean {
    val method = ZetaGuardAuthorizationCodeGrantType::class.java.getDeclaredMethod("useRefreshToken")
    method.isAccessible = true
    return method.invoke(grant) as Boolean
  }

  private fun invokeAddCustomTokenResponseClaims(
      grant: ZetaGuardAuthorizationCodeGrantType,
      response: AccessTokenResponse,
      clientSessionCtx: ClientSessionContext,
  ) {
    val method =
        ZetaGuardAuthorizationCodeGrantType::class.java.getDeclaredMethod(
            "addCustomTokenResponseClaims", AccessTokenResponse::class.java, ClientSessionContext::class.java)
    method.isAccessible = true
    method.invoke(grant, response, clientSessionCtx)
  }

  private fun invokeCreateTokenResponseBuilder(
      grant: ZetaGuardAuthorizationCodeGrantType,
      user: UserModel,
      userSession: UserSessionModel,
      clientSessionCtx: ClientSessionContext,
  ): TokenManager.AccessTokenResponseBuilder {
    val method =
        ZetaGuardAuthorizationCodeGrantType::class.java.getDeclaredMethod(
            "createTokenResponseBuilder",
            UserModel::class.java,
            UserSessionModel::class.java,
            ClientSessionContext::class.java,
            String::class.java,
            java.util.function.Function::class.java,
        )
    method.isAccessible = true
    try {
      @Suppress("UNCHECKED_CAST")
      return method.invoke(grant, user, userSession, clientSessionCtx, null, null) as TokenManager.AccessTokenResponseBuilder
    } catch (e: java.lang.reflect.InvocationTargetException) {
      throw e.targetException ?: e
    }
  }

  private fun setField(target: Any, type: Class<*>, name: String, value: Any?) {
    val field = type.getDeclaredField(name)
    field.isAccessible = true
    field.set(target, value)
  }
}
