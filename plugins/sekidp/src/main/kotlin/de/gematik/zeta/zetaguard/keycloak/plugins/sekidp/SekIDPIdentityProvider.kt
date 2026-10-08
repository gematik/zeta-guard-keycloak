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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_CREATED_AT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_LAST_ACCESS
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ORGANIZATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_MAX_CLIENTS
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.toISO8601
import de.gematik.zeta.zetaguard.keycloak.commons.server.toSpicyHash
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardExpirationService
import com.fasterxml.jackson.databind.JsonNode
import jakarta.ws.rs.core.UriBuilder
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap
import org.keycloak.OAuth2Constants
import org.keycloak.broker.oidc.OIDCIdentityProvider
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig
import org.keycloak.broker.provider.AuthenticationRequest
import org.keycloak.broker.provider.BrokeredIdentityContext
import org.keycloak.broker.provider.IdentityBrokerException
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider
import org.keycloak.common.util.Base64Url
import org.keycloak.common.util.SecretGenerator
import org.keycloak.common.util.Time
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.ECDSAAlgorithm
import org.keycloak.crypto.KeyType
import org.keycloak.events.EventBuilder
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.http.simple.SimpleHttpRequest
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jwk.JWKParser
import org.keycloak.jose.jws.JWSInput
import org.keycloak.models.IdentityProviderModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.cache.CachedUserModel
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.endpoints.AuthorizationEndpoint
import org.keycloak.protocol.oidc.utils.PkceUtils
import org.keycloak.protocol.oidc.utils.RedirectUtils
import org.keycloak.sessions.AuthenticationSessionModel
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.IDToken
import org.keycloak.representations.JsonWebToken
import org.keycloak.services.clientregistration.ClientRegistrationException
import org.keycloak.util.JsonSerialization
import java.security.Signature

private val maxClients = (System.getenv(ENV_MAX_CLIENTS) ?: "256").toInt()

/** ID-token claim carrying the KVNR (urn:telematik:versicherter scope). */
private const val CLAIM_TELEMATIK_KVNR = "urn:telematik:claims:id"

/** ID-token claim carrying the profession OID of the insured person (urn:telematik:versicherter scope). */
private const val CLAIM_TELEMATIK_PROFESSION = "urn:telematik:claims:profession"
private const val CLAIM_TELEMATIK_ORGANIZATION = "urn:telematik:claims:organization"

private const val SEKIDP_CONFIG_ACR_VALUES = "acrValues"
private const val SEKIDP_DEFAULT_ACR = "gematik-ehealth-loa-high"

private const val NOTE_BROKER_CODE_CHALLENGE = "BROKER_CODE_CHALLENGE"
private const val NOTE_BROKER_CODE_CHALLENGE_METHOD = "BROKER_CODE_CHALLENGE_METHOD"

// Must match Keycloak's private OIDCIdentityProvider.BROKER_NONCE_PARAM: the base class reads this client note
// in preprocessFederatedIdentity to verify the ID token's nonce echo. Since we override createAuthorizationUrl,
// we store it ourselves.
private const val NOTE_BROKER_NONCE = "BROKER_NONCE"

private const val SEKIDP_PARAM_IDP_ISS = "idp_iss"

/**
 * Where the SekIDP should redirect after authenticating the user.
 */
private const val SEKIDP_PARAM_OIDC_REDIRECT_URI = "oidc_redirect_uri"

/** The redirect_uri used for the inner flow; RFC 6749 requires the same value at the token request. */
private const val NOTE_OIDC_REDIRECT_URI = "SEKIDP_OIDC_REDIRECT_URI"

/** Key of the trusted issuer inside OIDCIdentityProviderConfig. */
private const val SEKIDP_CONFIG_ISSUER = "issuer"

/**
 * [sekIdpHttpClient] presents Keycloak's client certificate on PAR and token requests when mTLS is enabled
 */
class SekIDPIdentityProvider(
    session: KeycloakSession,
    config: OIDCIdentityProviderConfig,
    private val sekIdpHttpClient: SekIdpHttpClient,
) : OIDCIdentityProvider(session, config) {

  /** A set of signing keys (by `kid`) trusted for something, cached until [validUntil]. */
  private data class CachedKeys(val keysByKid: Map<String, JWK>, val validUntil: Int)

  /** A decoded entity statement body, cached until [validUntil]. */
  private data class CachedStatement(val body: JsonNode, val validUntil: Int)

  /** SekIDP endpoints taken from the IDP's entity statement, verified against [trustedIdpKeys]. */
  private data class SekIDPEndpoints(
      val pushedAuthorizationRequestEndpoint: String,
      val authorizationEndpoint: String,
      val tokenEndpoint: String,
      val signedJwksUri: String,
      val validUntil: Int,
  )

  private fun resolveOidcRedirectUri(authSession: AuthenticationSessionModel): String {
    val oidcRedirectUri =
        authSession.getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + SEKIDP_PARAM_OIDC_REDIRECT_URI)
            ?.trim()
            ?.takeIf { it.isNotBlank() }
            ?: throw IdentityBrokerException(
                "Missing $SEKIDP_PARAM_OIDC_REDIRECT_URI in the authorization request — the client has to name its /oidc callback")

    val client = authSession.client
    return RedirectUtils.verifyRedirectUri(session, oidcRedirectUri, client) ?: throw IdentityBrokerException(
        "$SEKIDP_PARAM_OIDC_REDIRECT_URI »$oidcRedirectUri« is not a registered redirect_uri of client »${client.clientId}«"
    )
  }

  private fun idpIssuerFromSession(authSession: AuthenticationSessionModel): String {
    val requested =
        authSession
            .getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + SEKIDP_PARAM_IDP_ISS)
            ?.trim()
            ?.trimEnd('/')
            ?.takeIf { it.isNotBlank() }
            ?: throw IdentityBrokerException("Missing $SEKIDP_PARAM_IDP_ISS in the authorization request — the client has to name the sectoral IDP")
    return requested
  }

  private fun fedmasterUrl(): String =
      providerConfig.config[SEKIDP_CONFIG_FEDMASTER_URL]?.trimEnd('/')
          ?: throw IdentityBrokerException("$SEKIDP_CONFIG_FEDMASTER_URL is not configured on the identity provider")

  /** Turns a JWKS JSON node (`{"keys": [...]}`) into a lookup map by `kid`, skipping keys without one. */
  private fun parseJwks(jwks: JsonNode): Map<String, JWK> =
      jwks.path("keys").mapNotNull { keyNode ->
        val jwk = JsonSerialization.mapper.treeToValue(keyNode, JWK::class.java)
        jwk.keyId?.let { it to jwk }
      }.toMap()

  private fun verifyAndDecode(jws: String, trustedKeys: Map<String, JWK>, what: String): JsonNode {
    val input =
        runCatching { JWSInput(jws) }.getOrElse { throw IdentityBrokerException("$what is not a JWS", it) }
    val kid = input.header.keyId ?: throw IdentityBrokerException("$what has no »kid« in its JWS header")
    val jwk = trustedKeys[kid] ?: throw IdentityBrokerException("$what is signed with unknown kid »$kid«")
    val algorithm = input.header.rawAlgorithm
    if (algorithm != Algorithm.ES256) {
      throw IdentityBrokerException("$what is signed with »$algorithm« — only ES256 is supported (algorithm profile per gemSpec_Krypt)")
    }
    val curve = jwk.otherClaims["crv"] as? String
    if (jwk.keyType != KeyType.EC || curve != "P-256") {
      throw IdentityBrokerException("$what: key »$kid« is not an EC/P-256 key (kty=${jwk.keyType}, crv=$curve)")
    }
    val publicKey = JWKParser.create(jwk).toPublicKey()
    val signatureBytes = ECDSAAlgorithm.concatenatedRSToASN1DER(input.signature, ECDSAAlgorithm.getSignatureLength(Algorithm.ES256))
    val signature = Signature.getInstance("SHA256withECDSA")
    signature.initVerify(publicKey)
    signature.update(input.encodedSignatureInput.toByteArray(StandardCharsets.UTF_8))
    if (!signature.verify(signatureBytes)) {
      throw IdentityBrokerException("$what has an invalid signature")
    }
    return JsonSerialization.mapper.readTree(input.content)
  }

  private fun fedmasterStatement(fedmasterUrl: String): JsonNode {
    fedmasterStatementCache?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return it.body
    }

    synchronized(fedmasterStatementLock) {
      fedmasterStatementCache?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return it.body
      }

      val statement = SimpleHttp.create(session).doGet("$fedmasterUrl/.well-known/openid-federation").asString()
      val parts = statement.split(".")
      if (parts.size != 3) {
        throw IdentityBrokerException("Federation Master entity statement of »$fedmasterUrl« is not a JWS")
      }
      val body = JsonSerialization.mapper.readTree(Base64Url.decode(parts[1]))
      val expiresAt = body.path("exp").asLong(0)
      fedmasterStatementCache =
          CachedStatement(body, minOf(expiresAt, (Time.currentTime() + ENDPOINT_CACHE_MAX_SECONDS).toLong()).toInt())
      return body
    }
  }

  private fun fedmasterSigningKeys(fedmasterUrl: String): Map<String, JWK> {
    val keysByKid = parseJwks(fedmasterStatement(fedmasterUrl).path("jwks"))
    if (keysByKid.isEmpty()) {
      throw IdentityBrokerException("Federation Master entity statement of »$fedmasterUrl« carries no jwks")
    }
    return keysByKid
  }

 // The Federation Master publishes its fetch endpoint as an absolute URL and it is used exactly as published.
  private fun fedmasterFetchEndpoint(fedmasterUrl: String): String =
      fedmasterStatement(fedmasterUrl)
          .path("metadata")
          .path("federation_entity")
          .path("federation_fetch_endpoint")
          .takeIf { it.isTextual }
          ?.asText()
          ?: throw IdentityBrokerException("Federation Master entity statement of »$fedmasterUrl« has no metadata.federation_entity.federation_fetch_endpoint")

  private fun trustedIdpKeys(fedmasterUrl: String, issuer: String): Map<String, JWK> {
    trustedIdpKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return it.keysByKid
    }

    synchronized(trustedIdpKeyLock) {
      trustedIdpKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return it.keysByKid
      }

      val fedmasterIssuer =
          fedmasterStatement(fedmasterUrl).path("iss").takeIf { it.isTextual }?.asText()
              ?: throw IdentityBrokerException("Federation Master entity statement of »$fedmasterUrl« has no iss")
      val statement =
          SimpleHttp.create(session)
              .doGet(fedmasterFetchEndpoint(fedmasterUrl))
              .param("iss", fedmasterIssuer)
              .param("sub", issuer)
              .asString()
      val body = verifyAndDecode(statement, fedmasterSigningKeys(fedmasterUrl), "Federation Master's statement about »$issuer«")
      val keysByKid = parseJwks(body.path("jwks"))
      if (keysByKid.isEmpty()) {
        throw IdentityBrokerException("Federation Master's statement about »$issuer« carries no jwks")
      }
      val expiresAt = body.path("exp").asLong(0)
      trustedIdpKeyCache[issuer] =
          CachedKeys(keysByKid, minOf(expiresAt, (Time.currentTime() + ENDPOINT_CACHE_MAX_SECONDS).toLong()).toInt())
      logger.infof("Federation Master vouches for »%s« with key(s): %s", issuer, keysByKid.keys)
      return keysByKid
    }
  }

  private fun discoverEndpoints(issuer: String): SekIDPEndpoints {
    endpointCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return it
    }

    synchronized(endpointLock) {
      endpointCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return it
      }

      val statement = SimpleHttp.create(session).doGet("$issuer/.well-known/openid-federation").asString()
      val trustedKeys = trustedIdpKeys(fedmasterUrl(), issuer)
      val body = verifyAndDecode(statement, trustedKeys, "SekIDP entity statement of »$issuer«")
      val openidProvider = body.path("metadata").path("openid_provider")
      fun endpoint(name: String): String =
          openidProvider.path(name).takeIf { it.isTextual }?.asText()
              ?: throw IdentityBrokerException("SekIDP entity statement of »$issuer« has no metadata.openid_provider.$name")

      val expiresAt = body.path("exp").asLong(0)
      val endpoints =
          SekIDPEndpoints(
              pushedAuthorizationRequestEndpoint = endpoint("pushed_authorization_request_endpoint"),
              authorizationEndpoint = endpoint("authorization_endpoint"),
              tokenEndpoint = endpoint("token_endpoint"),
              signedJwksUri = endpoint("signed_jwks_uri"),
              validUntil = minOf(expiresAt, (Time.currentTime() + ENDPOINT_CACHE_MAX_SECONDS).toLong()).toInt(),
          )
      endpointCache[issuer] = endpoints
      logger.infof("SekIDP endpoint discovery for »%s«: PAR=%s (trust chain verified)", issuer, endpoints.pushedAuthorizationRequestEndpoint)
      return endpoints
    }
  }

  /**
   * The keys the SekIDP signs its ID tokens with.
   *
   * A_22861: an ID-token signing key is resolved from the SekIDP's entity statement and the keys
   * behind its `signed_jwks_uri`.
   *
   * The Federation Master vouches for the IDP's *federation entity* key; that key signs both the entity
   * statement and the JWK set published at `signed_jwks_uri`, and only the latter carries the keys used
   * for the OIDC protocol itself.
   */
  private fun idTokenSigningKeys(issuer: String): Map<String, JWK> {
    idTokenSigningKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
      return it.keysByKid
    }

    synchronized(idTokenSigningKeyLock) {
      idTokenSigningKeyCache[issuer]?.takeIf { it.validUntil > Time.currentTime() }?.let {
        return it.keysByKid
      }

      val what = "SekIDP signed JWK set of »$issuer«"
      val signedJwks = SimpleHttp.create(session).doGet(discoverEndpoints(issuer).signedJwksUri).asString()
      val body = verifyAndDecode(signedJwks, trustedIdpKeys(fedmasterUrl(), issuer), what)

      // The entity statement names the URL; the document itself has to say whose keys these are.
      val declaredIssuer = body.path("iss").takeIf { it.isTextual }?.asText()?.trimEnd('/')
      if (declaredIssuer != issuer) {
        throw IdentityBrokerException("$what is issued for »$declaredIssuer«, not »$issuer«")
      }

      val keysByKid = parseJwks(body)
      if (keysByKid.isEmpty()) {
        throw IdentityBrokerException("$what carries no keys")
      }
      idTokenSigningKeyCache[issuer] = CachedKeys(keysByKid, Time.currentTime() + ENDPOINT_CACHE_MAX_SECONDS)
      logger.infof("SekIDP »%s« signs ID tokens with key(s): %s", issuer, keysByKid.keys)
      return keysByKid
    }
  }

  /**
   * Verifies the SekIDP's ID token against the protocol keys resolved through the federation trust chain.
   */
  override fun verify(jws: JWSInput): Boolean {
    val authSession = session.context?.authenticationSession
    val issuer = authSession?.let { runCatching { idpIssuerFromSession(it) }.getOrNull() }
    if (issuer == null) {
      logger.errorf("Cannot verify the SekIDP token: no %s on the authentication session", SEKIDP_PARAM_IDP_ISS)
      return false
    }
    return runCatching { verifyAndDecode(jws.wireString, idTokenSigningKeys(issuer), "SekIDP token of »$issuer«") }
        .onFailure { logger.errorf("SekIDP token signature rejected: %s", it.message) }
        .isSuccess
  }

  override fun createAuthorizationUrl(request: AuthenticationRequest): UriBuilder {
    val issuer = idpIssuerFromSession(request.authenticationSession)
    val endpoints = discoverEndpoints(issuer)

    val oidcRedirectUri = resolveOidcRedirectUri(request.authenticationSession)
    request.authenticationSession.setClientNote(NOTE_OIDC_REDIRECT_URI, oidcRedirectUri)

    val codeVerifier = PkceUtils.generateCodeVerifier()
    val codeChallenge = PkceUtils.encodeCodeChallenge(codeVerifier, OAuth2Constants.PKCE_METHOD_S256)
    request.authenticationSession.setClientNote(NOTE_BROKER_CODE_CHALLENGE, codeVerifier)
    request.authenticationSession.setClientNote(NOTE_BROKER_CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)

    val nonce = Base64Url.encode(SecretGenerator.getInstance().randomBytes(32))
    // Store the nonce so the base class verifies the ID token's nonce
    request.authenticationSession.setClientNote(NOTE_BROKER_NONCE, nonce)

    val requestUri =
        sekIdpHttpClient
            .doPost(session, endpoints.pushedAuthorizationRequestEndpoint)
            .param(OAUTH2_PARAMETER_CLIENT_ID, providerConfig.clientId)
            .param(OAUTH2_PARAMETER_STATE, request.state.encoded)
            .param(OAUTH2_PARAMETER_REDIRECT_URI, oidcRedirectUri)
            .param(OAuth2Constants.CODE_CHALLENGE, codeChallenge)
            .param(OAuth2Constants.CODE_CHALLENGE_METHOD, OAuth2Constants.PKCE_METHOD_S256)
            .param(OAUTH2_PARAMETER_RESPONSE_TYPE, OAuth2Constants.CODE)
            .param(OIDCLoginProtocol.NONCE_PARAM, nonce)
            .param(OAUTH2_PARAMETER_SCOPE, providerConfig.defaultScope)
            .param(OAuth2Constants.ACR_VALUES, providerConfig.config[SEKIDP_CONFIG_ACR_VALUES] ?: SEKIDP_DEFAULT_ACR)
            .asResponse()
            .use { response ->
              val parBody = response.asString()
              if (response.status != 201) {
                logger.errorf("SekIDP PAR at %s failed: HTTP %d %s", endpoints.pushedAuthorizationRequestEndpoint, response.status, parBody)
                throw IdentityBrokerException("SekIDP PAR failed with HTTP ${response.status}")
              }
              JsonSerialization.mapper.readTree(parBody).path("request_uri").takeIf { it.isTextual }?.asText()
                  ?: throw IdentityBrokerException("SekIDP PAR response contains no request_uri")
            }

    logger.infof("SekIDP PAR accepted, request_uri=%s", requestUri)
    return UriBuilder.fromUri(endpoints.authorizationEndpoint)
        .queryParam(OIDCLoginProtocol.REQUEST_URI_PARAM, requestUri)
        .queryParam(OAUTH2_PARAMETER_CLIENT_ID, providerConfig.clientId)
  }

  /**
   * Maps the telematik claims of the decrypted ID token: the KVNR (urn:telematik:claims:id) drives
   * the local username.
   */
  override fun extractIdentity(
      tokenResponse: AccessTokenResponse?,
      accessToken: String?,
      idToken: JsonWebToken,
  ): BrokeredIdentityContext {
    val identity = super.extractIdentity(tokenResponse, accessToken, idToken)
    val kvnr =
        idToken.otherClaims[CLAIM_TELEMATIK_KVNR] as? String
            ?: throw IdentityBrokerException("SekIDP ID token contains no $CLAIM_TELEMATIK_KVNR claim — was scope urn:telematik:versicherter requested?")
    val acr =
        (idToken.otherClaims[IDToken.ACR] as? String)?.takeIf { it.isNotBlank() }
            ?: throw IdentityBrokerException("SekIDP ID token contains no »${IDToken.ACR}« claim — the attested authentication level is unknown")
    val username = kvnr.toSpicyHash()
    identity.username = username
    identity.modelUsername = username
    identity.contextData[ATTRIBUTE_MOBILEUSER_KVNR] = kvnr
    identity.contextData[ATTRIBUTE_MOBILEUSER_ACR] = acr
    idToken.readAmr().takeIf { it.isNotEmpty() }?.let { identity.contextData[ATTRIBUTE_MOBILEUSER_AMR] = it.joinToString(" ") }
    (idToken.otherClaims[CLAIM_TELEMATIK_PROFESSION] as? String)?.takeIf { it.isNotBlank() }?.let {
      identity.contextData[ATTRIBUTE_MOBILEUSER_PROFESSION_OID] = it
    }
    (idToken.otherClaims[CLAIM_TELEMATIK_ORGANIZATION] as? String)?.takeIf { it.isNotBlank() }?.let {
      identity.contextData[ATTRIBUTE_MOBILEUSER_ORGANIZATION] = it
    }
    return identity
  }

  override fun authenticationFinished(authSession: AuthenticationSessionModel, context: BrokeredIdentityContext) {
    super.authenticationFinished(authSession, context)
    listOf(
            ATTRIBUTE_MOBILEUSER_KVNR,
            ATTRIBUTE_MOBILEUSER_ACR,
            ATTRIBUTE_MOBILEUSER_AMR,
            ATTRIBUTE_MOBILEUSER_PROFESSION_OID,
            ATTRIBUTE_MOBILEUSER_ORGANIZATION,
        )
        .forEach { note -> (context.contextData[note] as? String)?.let { authSession.setUserSessionNote(note, it) } }
  }

  override fun importNewUser(session: KeycloakSession, realm: RealmModel, userModel: UserModel, context: BrokeredIdentityContext) {
    val dataService = ZetaGuardDataService(DefaultEMCreator(session))

    dataService.createUserData(userModel.username)
    userModel.setSingleAttribute(ATTRIBUTE_MOBILEUSER_CREATED_AT, currentTime().toISO8601())

    updateBrokeredUser(session, realm, userModel, context)
  }

  override fun updateBrokeredUser(session: KeycloakSession, realm: RealmModel, user: UserModel, context: BrokeredIdentityContext) {
    val dataService = ZetaGuardDataService(DefaultEMCreator(session))

    val userModel = if (user is CachedUserModel) user.delegateForUpdate else user
    val clientId = session.context.client.clientId
    val userData =
        dataService.findUserData(userModel.username) ?: throw ClientRegistrationException("Could not find user data for »${userModel.username}«")
    val clientData = dataService.findClientData(clientId) ?: throw ClientRegistrationException("Could not find client data for »${clientId}«")
    val clientIds = userData.clients.map { it.id }.toMutableSet()
    val clientExpirationService = ZetaGuardExpirationService(session)
    val now = currentTime()

    if (clientIds.add(clientId)) { // A_25748-02
      if (clientIds.size > maxClients && !clientExpirationService.removeOldestClient(userModel.username)) {
        throw ClientRegistrationException("Too many clients for user »${userModel.username}«")
      }

      userData.clients.add(clientData)
      clientData.userData = userData

      (context.contextData[ATTRIBUTE_MOBILEUSER_KVNR] as? String)?.let { userModel.setSingleAttribute(ATTRIBUTE_MOBILEUSER_KVNR, it) }
    }

    userModel.setSingleAttribute(ATTRIBUTE_MOBILEUSER_LAST_ACCESS, now.toISO8601())
    userData.lastAccess = now
    clientData.lastAccess = now
  }

  /**
   * Binds this request to the sectoral IDP that was actually chosen via `idp_iss`.
   *
   * The base class reads `tokenUrl` and the trusted `issuer` straight from the provider config, which is
   * static — with a client-selected IDP both must follow the resolved issuer instead. Always goes through
   * [discoverEndpoints] (trust-chain verified) — no static fallback anymore, so the token endpoint is
   * never used un-verified even for what used to be the one "default" issuer. Reads the SAME raw client
   * note [idpIssuerFromSession] does (Keycloak sets the authentication session on the context before the
   * inner token exchange, so it's still there) — with the same normalisation, so this can't ever disagree
   * with what [discoverEndpoints] used as its cache key. We hand back a per-request COPY: mutating the
   * shared provider model would leak one login's IDP into the next.
   */
  override fun getConfig(): OIDCIdentityProviderConfig {
    val base = super.config
    val resolved =
        session.context?.authenticationSession
            ?.getClientNote(AuthorizationEndpoint.LOGIN_SESSION_NOTE_ADDITIONAL_REQ_PARAMS_PREFIX + SEKIDP_PARAM_IDP_ISS)
            ?.trim()
            ?.trimEnd('/')
            ?.takeIf { it.isNotBlank() }
            ?: return base

    return OIDCIdentityProviderConfig(IdentityProviderModel(base)).apply {
      config[SEKIDP_CONFIG_ISSUER] = resolved
      tokenUrl = discoverEndpoints(resolved).tokenEndpoint
    }
  }

  /** The provider config as stored, without the per-request issuer rebinding done by [getConfig]. */
  private val providerConfig: OIDCIdentityProviderConfig
    get() = super.config

  /** Token endpoint of the IDP resolved for THIS request (see [getConfig]). */
  private fun effectiveTokenUrl(): String = getConfig().tokenUrl

  override fun callback(
      realm: RealmModel,
      callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
      event: EventBuilder,
  ): Any = SekIDPEndpoint(callback, realm, event, this, session)

  private class SekIDPEndpoint(
      callback: UserAuthenticationIdentityProvider.AuthenticationCallback,
      realm: RealmModel,
      event: EventBuilder,
      private val sekProvider: SekIDPIdentityProvider,
      private val kcSession: KeycloakSession,
  ) : Endpoint(callback, realm, event, sekProvider) {

    override fun generateTokenRequest(authorizationCode: String): SimpleHttpRequest {
      val authSession = kcSession.context?.authenticationSession
      val redirectUri =
          authSession?.getClientNote(NOTE_OIDC_REDIRECT_URI)?.takeIf { it.isNotBlank() }
              ?: throw IdentityBrokerException(
                  "No $SEKIDP_PARAM_OIDC_REDIRECT_URI on the authentication session — cannot build the token request")

      val tokenRequest =
          sekProvider.sekIdpHttpClient
              .doPost(kcSession, sekProvider.effectiveTokenUrl())
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

  companion object {
    /** Cap for the discovery cache so a long-lived entity statement cannot pin stale endpoints. */
    private const val ENDPOINT_CACHE_MAX_SECONDS = 300

    /** There is exactly one Federation Master — a single cached value, not a map keyed by URL. */
    @Volatile private var fedmasterStatementCache: CachedStatement? = null
    private val fedmasterStatementLock = Any()

    /** Per sectoral IDP (`issuer`) — several of these ARE expected once more SekIDPs are configured. */
    private val endpointCache = ConcurrentHashMap<String, SekIDPEndpoints>()
    private val endpointLock = Any()

    /** The key(s) the Federation Master vouches for one sectoral IDP, keyed by issuer. */
    private val trustedIdpKeyCache = ConcurrentHashMap<String, CachedKeys>()
    private val trustedIdpKeyLock = Any()

    /** The ID-token signing key(s) from one sectoral IDP's `signed_jwks_uri`, keyed by issuer. */
    private val idTokenSigningKeyCache = ConcurrentHashMap<String, CachedKeys>()
    private val idTokenSigningKeyLock = Any()
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
