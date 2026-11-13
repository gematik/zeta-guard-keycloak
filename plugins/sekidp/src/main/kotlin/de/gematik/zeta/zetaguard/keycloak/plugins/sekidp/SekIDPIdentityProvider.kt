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

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.getOrElse
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.AbstractZetaGuardIdentityProvider
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_BIRTHDATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_DISPLAY_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ORGANIZATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.plugins.toWritableUser
import jakarta.ws.rs.GET
import jakarta.ws.rs.QueryParam
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.UriBuilder
import java.time.LocalDate
import org.apache.http.HttpStatus
import org.keycloak.OAuth2Constants
import org.keycloak.OAuth2Constants.ACR_VALUES
import org.keycloak.OAuth2Constants.CODE
import org.keycloak.OAuth2Constants.CODE_CHALLENGE
import org.keycloak.OAuth2Constants.CODE_CHALLENGE_METHOD
import org.keycloak.OAuth2Constants.PKCE_METHOD_S256
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityBrokerException
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.common.util.SecretGenerator
import org.keycloak.events.EventBuilder
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.http.simple.SimpleHttpRequest
import org.keycloak.jose.jws.JWSInput
import org.keycloak.models.FederatedIdentityModel
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.OIDCLoginProtocol.NONCE_PARAM
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.IDToken
import org.keycloak.representations.JsonWebToken
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.util.JsonSerialization

/** ID-token claim carrying the KVNR (urn:telematik:versicherter scope). */
private const val CLAIM_TELEMATIK_KVNR = "urn:telematik:claims:id"

/** ID-token claim carrying the profession OID of the insured person (urn:telematik:versicherter scope). */
private const val CLAIM_TELEMATIK_PROFESSION = "urn:telematik:claims:profession"
private const val CLAIM_TELEMATIK_ORGANIZATION = "urn:telematik:claims:organization"

/** ID-token claim carrying the insured person's full display name, mapped onto commonName (A_26973-03). */
private const val CLAIM_TELEMATIK_DISPLAY_NAME = "urn:telematik:claims:display_name"

/** Consent-dependent ID-token claim (scope urn:telematik:geburtsdatum), YYYY-MM-DD per OpenID Connect Core 5.1 (A_26973-03). */
private const val CLAIM_BIRTHDATE = "birthdate"
private val BIRTHDATE_FORMAT = Regex("""\d{4}-\d{2}-\d{2}""")

private const val SEKIDP_CONFIG_ACR_VALUES = "acrValues"
const val SEKIDP_DEFAULT_ACR = "gematik-ehealth-loa-high"

private const val NOTE_BROKER_CODE_CHALLENGE = "BROKER_CODE_CHALLENGE"
private const val NOTE_BROKER_CODE_CHALLENGE_METHOD = "BROKER_CODE_CHALLENGE_METHOD"

// Must match Keycloak's private OIDCIdentityProvider.BROKER_NONCE_PARAM: the base class reads this client note
// in preprocessFederatedIdentity to verify the ID token's nonce echo (A_29672). Since we override
// createAuthorizationUrl, we store it ourselves.
private const val NOTE_BROKER_NONCE = "BROKER_NONCE"

private const val SEKIDP_PARAM_IDP_ISS = "idp_iss"

/**
 * Where the SekIDP should redirect after authenticating the user.
 */
private const val SEKIDP_PARAM_OIDC_REDIRECT_URI = "oidc_redirect_uri"

/** The redirect_uri used for the inner flow; RFC 6749 requires the same value at the token request. */
private const val NOTE_OIDC_REDIRECT_URI = "SEKIDP_OIDC_REDIRECT_URI"

/** A parameter the client added to the authorization request; blank counts as absent. */
private fun AuthenticationSessionModel.requestParam(name: String): String? =
    getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + name)?.trim()?.takeIf { it.isNotBlank() }

/** The sectoral IDP the client named via `idp_iss`, normalised; null when this request carries none. */
private val AuthenticationSessionModel.sekIdpIssuer: String?
  get() = requestParam(SEKIDP_PARAM_IDP_ISS)?.trimEnd('/')?.takeIf { it.isNotBlank() }

/** Key of the trusted issuer inside OIDCIdentityProviderConfig. */
private const val SEKIDP_CONFIG_ISSUER = "issuer"

/**
 * A_26973-02: the user data of the ID token that is kept at the user, as user attributes. Their values are encrypted by the
 * integrity provider (`UserAttributeEntity.value` in spree-configuration.yml). acr and amr describe a single authentication,
 * not the user, and stay user session notes only.
 */
private val PERSISTED_USER_DATA =
    listOf(
        ATTRIBUTE_MOBILEUSER_KVNR,
        ATTRIBUTE_MOBILEUSER_DISPLAY_NAME,
        ATTRIBUTE_MOBILEUSER_BIRTHDATE,
        ATTRIBUTE_MOBILEUSER_PROFESSION_OID,
        ATTRIBUTE_MOBILEUSER_ORGANIZATION,
    )

/**
 * [sekIdpHttpClient] presents Keycloak's client certificate on PAR and token requests when mTLS is enabled
 */
class SekIDPIdentityProvider(
    session: KeycloakSession,
    config: OIDCIdentityProviderConfig,
    private val sekIdpHttpClient: SimpleHttp,
    private val integrityProviderService: IntegrityProviderService,
    fedmasterUrl: String,
) : AbstractZetaGuardIdentityProvider(session, config) {

  private val federation = Federation(session, fedmasterUrl)

  /** `state_as -> AUTH_SESSION_ID` cookie value. */
  private val cookieValueByStateAs = AuthSessionCookieValueByStateAs(session)

  /** [OuterParExecutor] already checked it against the client's registered redirect_uris. */
  private fun resolveOidcRedirectUri(authSession: AuthenticationSessionModel): Either<IdentityBrokerException, String> = either {
    authSession.requestParam(SEKIDP_PARAM_OIDC_REDIRECT_URI)
      ?: raise(
          IdentityBrokerException(
              "Missing $SEKIDP_PARAM_OIDC_REDIRECT_URI in the authorization request — the client has to name its /oidc callback"
          )
      )
  }

  /**
   * Verifies the SekIDP's ID token against the protocol keys resolved through the federation trust chain.
   */
  public override fun verify(jws: JWSInput): Boolean = either<IdentityBrokerException, Unit> {
    val sekIdpIssuer =
        session.context?.authenticationSession?.sekIdpIssuer ?: raise(SekIdpIdentityError.MissingIdpIss.toIdentityBrokerException())
    val sekIdp = federation.sekIdp(sekIdpIssuer).mapLeft { it.toIdentityBrokerException() }.bind()
    sekIdp.verifyIdToken(jws.wireString).mapLeft { it.toIdentityBrokerException() }.bind()
  }.fold(
      ifLeft = {
        logger.errorf("SekIDP token rejected: %s", it.message)
        false
      },
      ifRight = { true }
  )

  /** A_29660: pushes the inner authorization request to the SekIDP and returns the URL carrying its `request_uri`. */
  public override fun createAuthorizationUrl(request: AuthenticationRequest): UriBuilder = either {
    val sekIdpIssuer =
        request.authenticationSession.sekIdpIssuer
          ?: raise(IdentityBrokerException("Missing $SEKIDP_PARAM_IDP_ISS in the authorization request — the client has to name the sectoral IDP"))
    val sekIdp = federation.sekIdp(sekIdpIssuer).mapLeft { it.toIdentityBrokerException() }.bind()
    val endpoints = sekIdp.resolveEndpoints().mapLeft { it.toIdentityBrokerException() }.bind()
    val oidcRedirectUri = resolveOidcRedirectUri(request.authenticationSession).bind()

    request.authenticationSession.setClientNote(NOTE_OIDC_REDIRECT_URI, oidcRedirectUri)

    val codeVerifier = PkceUtils.generateCodeVerifier()
    val codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, PKCE_METHOD_S256)

    request.authenticationSession.setClientNote(NOTE_BROKER_CODE_CHALLENGE, codeVerifier)
    request.authenticationSession.setClientNote(NOTE_BROKER_CODE_CHALLENGE_METHOD, PKCE_METHOD_S256)

    val nonce = SecretGenerator.getInstance().randomBytes(32).toBase64()
    // Store the nonce so the base class verifies the ID token's nonce
    request.authenticationSession.setClientNote(NOTE_BROKER_NONCE, nonce)

    val stateAs = request.state.encoded
    val requestUri =
        pushAuthorizationRequest(
            endpoints = endpoints,
            state = stateAs,
            oidcRedirectUri = oidcRedirectUri,
            codeChallenge = codeChallenge,
            nonce = nonce,
        ).mapLeft { it.toIdentityBrokerException() }.bind()

    // A_29671: the ZETA Client brings state_as, not a cookie, to the Redirection Endpoint.
    cookieValueByStateAs.store(stateAs, request.authenticationSession)

    UriBuilder.fromUri(endpoints.authorizationEndpoint)
        .queryParam(OIDCLoginProtocol.REQUEST_URI_PARAM, requestUri)
        .queryParam(OAUTH2_PARAMETER_CLIENT_ID, providerConfig.clientId)
  }.fold(
      ifLeft = { throw it },
      ifRight = { it }
  )

  /** A_29660: posts the inner authorization request and returns the `request_uri` the SekIDP hands back for it. */
  private fun pushAuthorizationRequest(
      endpoints: SekIDPEndpoints,
      state: String,
      oidcRedirectUri: String,
      codeChallenge: String,
      nonce: String,
  ): Either<SekIdpAuthorizationRequestError, String> = either {
    sekIdpHttpClient
        .doPost(endpoints.pushedAuthorizationRequestEndpoint)
        .param(OAUTH2_PARAMETER_CLIENT_ID, providerConfig.clientId)
        .param(OAUTH2_PARAMETER_STATE, state)
        .param(OAUTH2_PARAMETER_REDIRECT_URI, oidcRedirectUri)
        .param(CODE_CHALLENGE, codeChallenge)
        .param(CODE_CHALLENGE_METHOD, PKCE_METHOD_S256)
        .param(OAUTH2_PARAMETER_RESPONSE_TYPE, CODE)
        .param(NONCE_PARAM, nonce)
        .param(OAUTH2_PARAMETER_SCOPE, providerConfig.defaultScope)
        .param(ACR_VALUES, providerConfig.config[SEKIDP_CONFIG_ACR_VALUES] ?: SEKIDP_DEFAULT_ACR)
        .asResponse()
        .use { response ->
          val body = response.asString()

          ensure(response.status == HttpStatus.SC_CREATED) {
            logger.errorf("SekIDP PAR at %s failed: HTTP %d %s", endpoints.pushedAuthorizationRequestEndpoint, response.status, body)
            SekIdpAuthorizationRequestError.Rejected(response.status, body)
          }

          JsonSerialization.mapper.readTree(body).path("request_uri").takeIf { it.isTextual }?.asText()
            ?: raise(SekIdpAuthorizationRequestError.MissingRequestUri(body))
        }
        .also { logger.infof("SekIDP PAR accepted, request_uri=%s", it) }
  }

  /**
   * Maps the telematik claims of the decrypted ID token: the KVNR (urn:telematik:claims:id) drives
   * the local username, urn:telematik:claims:display_name becomes commonName (A_26973-03). The consent-dependent
   * birthdate is optional — its absence is no error.
   */
  override fun extractIdentity(
      tokenResponse: AccessTokenResponse,
      accessToken: String,
      idToken: JsonWebToken,
  ): BrokeredIdentityContext = either {
    val identity = super.extractIdentity(tokenResponse, accessToken, idToken)
    val kvnr = idToken.otherClaims[CLAIM_TELEMATIK_KVNR] as? String ?: raise(SekIdpIdentityError.MissingKvnr.toIdentityBrokerException())
    val acr = (idToken.otherClaims[IDToken.ACR] as? String)?.takeIf { it.isNotBlank() }
      ?: raise(SekIdpIdentityError.MissingAcr.toIdentityBrokerException())
    val displayName = (idToken.otherClaims[CLAIM_TELEMATIK_DISPLAY_NAME] as? String)?.takeIf { it.isNotBlank() }
      ?: raise(SekIdpIdentityError.MissingDisplayName.toIdentityBrokerException())
    val username = kvnr.toSpicyHash()

    identity.username = username
    identity.modelUsername = username
    identity.contextData[ATTRIBUTE_MOBILEUSER_KVNR] = kvnr
    identity.contextData[ATTRIBUTE_MOBILEUSER_ACR] = acr
    identity.contextData[ATTRIBUTE_MOBILEUSER_DISPLAY_NAME] = displayName

    idToken.readAmr().takeIf { it.isNotEmpty() }?.let { identity.contextData[ATTRIBUTE_MOBILEUSER_AMR] = it.joinToString(" ") }

    (idToken.otherClaims[CLAIM_TELEMATIK_PROFESSION] as? String)?.takeIf { it.isNotBlank() }?.let {
      identity.contextData[ATTRIBUTE_MOBILEUSER_PROFESSION_OID] = it
    }
    (idToken.otherClaims[CLAIM_TELEMATIK_ORGANIZATION] as? String)?.takeIf { it.isNotBlank() }?.let {
      identity.contextData[ATTRIBUTE_MOBILEUSER_ORGANIZATION] = it
    }
    idToken.readBirthdate()?.let { identity.contextData[ATTRIBUTE_MOBILEUSER_BIRTHDATE] = it }

    identity
  }.fold(
      ifLeft = { throw it },
      ifRight = { it }
  )

  /**
   * The birthdate claim if it is a valid YYYY-MM-DD date. Anything else is dropped rather than rejected: the claim is
   * optional, and passing a malformed value on would only break the PEP's ZETA-User-Info downstream.
   *
   * Both checks are needed: the regex rejects the signed or longer years `LocalDate.parse` accepts (`+10000-01-01`,
   * `-0001-01-01`), `LocalDate.parse` rejects dates that do not exist (`1987-02-30`).
   */
  private fun JsonWebToken.readBirthdate(): String? {
    val raw = otherClaims[CLAIM_BIRTHDATE] ?: return null
    val birthdate = (raw as? String)?.takeIf { BIRTHDATE_FORMAT.matches(it) && Either.catch { LocalDate.parse(it) }.isRight() }
    if (birthdate == null) logger.warnf("Ignoring SekIDP birthdate claim that is no YYYY-MM-DD date: »%s«", raw)
    return birthdate
  }

  override fun authenticationFinished(authSession: AuthenticationSessionModel, context: BrokeredIdentityContext) {
    super.authenticationFinished(authSession, context)

    listOf(
        ATTRIBUTE_MOBILEUSER_KVNR,
        ATTRIBUTE_MOBILEUSER_ACR,
        ATTRIBUTE_MOBILEUSER_AMR,
        ATTRIBUTE_MOBILEUSER_PROFESSION_OID,
        ATTRIBUTE_MOBILEUSER_ORGANIZATION,
        ATTRIBUTE_MOBILEUSER_DISPLAY_NAME,
        ATTRIBUTE_MOBILEUSER_BIRTHDATE,
    ).forEach { note -> (context.contextData[note] as? String)?.let { authSession.setUserSessionNote(note, it) } }
  }

  /**
   * A_26973-02: stores the user data of the ID token at the user on every login, not only when a client is bound to the user
   * for the first time — a changed display name or a withdrawn birthdate consent has to reach the database as well.
   */
  override fun updateBrokeredUser(session: KeycloakSession, realm: RealmModel, user: UserModel, context: BrokeredIdentityContext) {
    super.updateBrokeredUser(session, realm, user, context)

    user.toWritableUser().storeUserData(context)
  }

  /** Nothing extra for a newly bound client: [updateBrokeredUser] stores the user data on every login. */
  override fun updateUserModel(context: BrokeredIdentityContext, userModel: UserModel) = Unit

  override fun professionOid(context: BrokeredIdentityContext): String? = context.contextData[ATTRIBUTE_MOBILEUSER_PROFESSION_OID] as? String

  /** The login stores the user data of the ID token (A_26973-02), which must not end up in the database unencrypted. */
  fun checkIntegrityProvider(): Either<KeycloakError, Unit> = either {
    ensure(!integrityProviderService.isIntegrityProviderEnabled() || integrityProviderService.isIntegrityProviderRunning()) {
      SekIdpRedirectionError.integrityProviderNotRunning()
    }
  }

  /**
   * Binds this request to the sectoral IDP the client named in its `idp_iss` client note.
   *
   * Two settings must follow that choice rather than the stored config: `issuer`, which `validateToken` checks the ID
   * token's `iss` against (A_29672), and `tokenUrl`, where [SekIDPEndpoint.generateTokenRequest] posts the code. Following the raw
   * note is safe because [Federation] only hands out IDPs the Federation Master vouches for. Returns a copy —
   * mutating the shared model would leak one login's IDP into the next.
   *
   * Falls back to the stored config outside a login (logout, admin), where no authentication session carries `idp_iss`.
   */
  override fun getConfig(): OIDCIdentityProviderConfig {
    val base = super.config
    val sekIdpIssuer = session.context?.authenticationSession?.sekIdpIssuer ?: return base

    return OIDCIdentityProviderConfig(IdentityProviderModel(base)).apply {
      config[SEKIDP_CONFIG_ISSUER] = sekIdpIssuer
      tokenUrl =
          federation.sekIdp(sekIdpIssuer).flatMap { it.resolveEndpoints() }.getOrElse { throw it.toIdentityBrokerException() }.tokenEndpoint
    }
  }

  /** The provider config as stored, without the per-request issuer rebinding done by [getConfig]. */
  private val providerConfig: OIDCIdentityProviderConfig
    get() = super.config

  /**
   * Hands JAX-RS the resource serving `/realms/{realm}/broker/{alias}/endpoint`.
   *
   * The untyped return is the interface's: JAX-RS inspects the object for its own annotations. Sole reason for the
   * override is [SekIDPEndpoint], which guards the Redirection Endpoint with the `state_as` mapping and replaces
   * `generateTokenRequest`.
   */
  override fun callback(
      realm: RealmModel,
      callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
      event: EventBuilder,
  ): Any = SekIDPEndpoint(callback, realm, event, this)

  fun checkKnownStateAs(state: String): Either<KeycloakError, Unit> = either {
    ensure(cookieValueByStateAs.lookup(state) != null) {
      logger.warnf("Redirection Endpoint called with a state_as the mapping does not know: %s", state)
      SekIdpRedirectionError.unknownStateAs()
    }
  }

  /**
   * Creates user and Federated Identity for a First Login before core looks the user up.
   *
   * Keycloak would otherwise redirect a user without Federated Identity through the cookie-bound `first-broker-login`
   * requests.
   */
  fun provisionFirstLogin(realm: RealmModel, context: BrokeredIdentityContext): Either<KeycloakError, Unit> = either {
    val users = session.users()
    val link = FederatedIdentityModel(context.idpConfig.alias, context.id, context.username, null)
    if (users.getUserByFederatedIdentity(realm, link) != null) return@either

    val username = context.modelUsername
    ensure(users.getUserByUsername(realm, username) == null) {
      logger.warnf("First Login for a user that exists without Federated Identity: %s", username)
      SekIdpRedirectionError.identityAlreadyRegistered()
    }

    val user = users.addUser(realm, username).apply { isEnabled = true }
    users.addFederatedIdentity(realm, user, link)
    session.context.client = context.authenticationSession.client
    importNewUser(session, realm, user, context)
  }

  class SekIDPAuthenticationCallback(
      private val delegate: UserAuthenticationIdentityProvider.AuthenticationCallback,
      private val cookieValueByStateAs: AuthSessionCookieValueByStateAs,
      private val checkIntegrityProvider: () -> Either<KeycloakError, Unit>,
      private val provisionFirstLogin: (BrokeredIdentityContext) -> Either<KeycloakError, Unit>,
  ) : UserAuthenticationIdentityProvider.AuthenticationCallback by delegate {

    /** The `state_as` of the request in flight. */
    private var stateAs: String? = null

    /**
     * Keycloak's first step in `authResponse`, before the token request and [authenticated]: it decodes `state`, reads the
     * `AUTH_SESSION_ID` cookie (served by [ZetaCookieProvider]) and resolves the Authentication Session.
     */
    override fun getAndVerifyAuthenticationSession(encodedCode: String): AuthenticationSessionModel {
      stateAs = encodedCode
      return delegate.getAndVerifyAuthenticationSession(encodedCode)
    }

    override fun authenticated(context: BrokeredIdentityContext): Response =
        either {
          checkIntegrityProvider().bind()
          provisionFirstLogin(context).bind()
          val stateAs = stateAs ?: return@either
          ensure(cookieValueByStateAs.remove(stateAs)) {
            logger.warnf("Redirection Endpoint: state_as was already used: %s", stateAs)
            SekIdpRedirectionError.unknownStateAs()
          }
        }.fold(
            ifLeft = { it.toResponse() },
            ifRight = { delegate.authenticated(context) },
        )
  }

  /** The Redirection Endpoint as the ZETA Client calls it. */
  private class SekIDPEndpoint(
      callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
      realm: RealmModel,
      event: EventBuilder,
      private val sekProvider: SekIDPIdentityProvider,
  ) :
    Endpoint(
        SekIDPAuthenticationCallback(callback, sekProvider.cookieValueByStateAs, sekProvider::checkIntegrityProvider) {
          sekProvider.provisionFirstLogin(realm, it)
        },
        realm,
        event,
        sekProvider,
    ) {

    @GET
    override fun authResponse(
        @QueryParam(OAUTH2_PARAMETER_STATE) state: String?,
        @QueryParam(OAUTH2_PARAMETER_CODE) authorizationCode: String?,
        @QueryParam(OAuth2Constants.ERROR) error: String?,
        @QueryParam(OAuth2Constants.ERROR_DESCRIPTION) errorDescription: String?,
    ): Response {
      if (state != null) {
        sekProvider.checkKnownStateAs(state).getOrElse { return it.toResponse() }
        ZetaCookieProvider.attachStateAsToSession(sekProvider.session, state)
      }
      return super.authResponse(state, authorizationCode, error, errorDescription)
    }

    override fun generateTokenRequest(authorizationCode: String): SimpleHttpRequest {
      val authSession = sekProvider.session.context?.authenticationSession
      val redirectUri =
          authSession?.getClientNote(NOTE_OIDC_REDIRECT_URI)?.takeIf { it.isNotBlank() }
            ?: throw IdentityBrokerException(
                "No $SEKIDP_PARAM_OIDC_REDIRECT_URI on the authentication session — cannot build the token request"
            )

      val tokenRequest =
          sekProvider.sekIdpHttpClient
              .doPost(sekProvider.config.tokenUrl)
              .param(OAUTH2_PARAMETER_CODE, authorizationCode)
              .param(OAUTH2_PARAMETER_REDIRECT_URI, redirectUri)
              .param(OAUTH2_PARAMETER_GRANT_TYPE, OAUTH2_GRANT_TYPE_AUTHORIZATION_CODE)
              .param(OAUTH2_PARAMETER_CLIENT_ID, sekProvider.providerConfig.clientId)
      authSession.getClientNote(NOTE_BROKER_CODE_CHALLENGE)?.let {
        tokenRequest.param(OAuth2Constants.CODE_VERIFIER, it)
      }

      logger.debugf("Token request repeats redirect_uri=%s", redirectUri)

      return sekProvider.authenticateTokenRequest(tokenRequest)
    }
  }
}

/**
 * Mirrors [PERSISTED_USER_DATA] from the context data onto the user (A_26973-02): a claim the ID token carries is set, one it
 * lacks — e.g. the birthdate after a withdrawn consent — is removed. Unchanged values are left alone to spare the database a write.
 */
internal fun UserModel.storeUserData(context: BrokeredIdentityContext) {
  PERSISTED_USER_DATA.forEach { name ->
    val value = context.contextData[name] as? String
    val stored = getFirstAttribute(name)

    when {
      value == null -> if (stored != null) removeAttribute(name)
      value != stored -> setSingleAttribute(name, value)
    }
  }
}

private fun JsonWebToken.readAmr(): List<String> {
  val raw = otherClaims[OAuth2Constants.AUTHENTICATOR_METHOD_REFERENCE] ?: return emptyList()
  val values =
      when (raw) {
        is Collection<*> -> raw.mapNotNull { it?.toString() }
        is Array<*> -> raw.mapNotNull { it?.toString() }
        else -> listOf(raw.toString())
      }
  return values.map { it.trim() }.filter { it.isNotBlank() }
}
