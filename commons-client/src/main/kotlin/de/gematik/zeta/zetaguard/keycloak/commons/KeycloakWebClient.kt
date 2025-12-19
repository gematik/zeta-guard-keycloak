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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import arrow.core.Either
import arrow.core.left
import arrow.core.merge
import arrow.core.right
import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_VALID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_ATTESTATION_STATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakSuccessResponse
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_FULL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.VALID_GRANT_TYPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.message
import java.io.BufferedReader
import kotlin.time.Duration.Companion.minutes
import org.apache.http.HttpHeaders.ACCEPT
import org.apache.http.HttpHeaders.AUTHORIZATION
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.HttpResponse
import org.apache.http.HttpStatus.SC_CREATED
import org.apache.http.HttpStatus.SC_OK
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.client.methods.RequestBuilder.get
import org.apache.http.client.methods.RequestBuilder.post
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.conn.ssl.TrustAllStrategy
import org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED
import org.apache.http.entity.ContentType.APPLICATION_JSON
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContextBuilder
import org.keycloak.OAuth2Constants.ACCESS_TOKEN_TYPE
import org.keycloak.OAuth2Constants.AUDIENCE
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.OAuth2Constants.CLIENT_ID
import org.keycloak.OAuth2Constants.CLIENT_SECRET
import org.keycloak.OAuth2Constants.DPOP_HTTP_HEADER
import org.keycloak.OAuth2Constants.GRANT_TYPE
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.OAuth2Constants.PASSWORD
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.REFRESH_TOKEN_TYPE
import org.keycloak.OAuth2Constants.REQUESTED_TOKEN_TYPE
import org.keycloak.OAuth2Constants.SCOPE
import org.keycloak.OAuth2Constants.SCOPE_OPENID
import org.keycloak.OAuth2Constants.SUBJECT_TOKEN
import org.keycloak.OAuth2Constants.SUBJECT_TOKEN_TYPE
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.OAuth2Constants.USERNAME
import org.keycloak.admin.client.resource.BearerAuthFilter.AUTH_HEADER_PREFIX
import org.keycloak.crypto.Algorithm.ES256
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.models.Constants.REALM_CLIENT
import org.keycloak.models.utils.KeycloakModelUtils.AUTH_TYPE_CLIENT_SECRET
import org.keycloak.protocol.oidc.OIDCAdvancedConfigWrapper.TokenExchangeRefreshTokenEnabled.SAME_SESSION
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_ENABLED
import org.keycloak.protocol.oidc.OIDCConfigAttributes.STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED
import org.keycloak.protocol.oidc.OIDCLoginProtocol.PRIVATE_KEY_JWT
import org.keycloak.protocol.oidc.utils.OIDCResponseType
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.UserInfo
import org.keycloak.representations.idm.ClientInitialAccessCreatePresentation
import org.keycloak.representations.idm.ClientInitialAccessPresentation
import org.keycloak.representations.idm.ClientRepresentation
import org.keycloak.representations.oidc.OIDCClientRepresentation

typealias KeycloakResponse<T> = Either<KeycloakError, KeycloakSuccessResponse<T>>

/**
 * A web client for interacting with Keycloak.
 *
 * @param hostname The hostname of the Keycloak server.
 * @param port The port of the Keycloak server.
 */
// class KeycloakWebClient(hostname: String = KC_HOST, port: Int = KC_PORT) : KeycloakAdminClient("zeta-dev.westeurope.cloudapp.azure.com", 443,
// "https", path = "/auth") {
class KeycloakWebClient(hostname: String = KC_HOST, port: Int = KC_PORT) : KeycloakAdminClient(hostname, port, "http") {
  private var currentBody: String? = null

  /**
   * Logs in a user and returns an access token.
   *
   * @param realm The realm to authenticate against.
   * @param user The username.
   * @param password The user's password.
   * @param client The client ID.
   * @param clientSecret The client secret.
   * @param requestedClientScope The requested client scope.
   * @return A [KeycloakResponse] containing an [AccessTokenResponse].
   */
  fun login(
      realm: String = ZETA_REALM,
      user: String = USER1,
      password: String = USER1_PASSWORD,
      client: String,
      clientSecret: String? = null,
      requestedClientScope: String? = null,
  ): KeycloakResponse<AccessTokenResponse> {
    val request =
        post(uriBuilder().tokenUrl(realm))
            .addFormHeaders()
            .addParameter(CLIENT_ID, client)
            .addParameter(USERNAME, user)
            .addParameter(PASSWORD, password)
            .addParameter(GRANT_TYPE, PASSWORD)

    if (clientSecret != null) {
      request.addParameter(CLIENT_SECRET, clientSecret)
    }

    if (requestedClientScope != null) {
      request.addParameter(SCOPE, requestedClientScope)
    }

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<AccessTokenResponse>()
  }

  fun getNonce(): KeycloakResponse<String> {
    val request = get(uriBuilder().createUri(NONCE_FULL_PATH, ZETA_REALM))

    return createHttpClient().use { it.execute(request.build()) }.mapStringResponse()
  }

  fun refreshToken(refreshToken: String, clientAssertion: String, dPoPToken: String): KeycloakResponse<AccessTokenResponse> {
    val request =
        post(uriBuilder().tokenUrl())
            .addFormHeaders()
            .addHeader(DPOP_HTTP_HEADER, dPoPToken)
            .addParameter(GRANT_TYPE, REFRESH_TOKEN)
            .addParameter(REFRESH_TOKEN, refreshToken)
            .addParameter(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT)
            .addParameter(CLIENT_ASSERTION, clientAssertion)

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<AccessTokenResponse>()
  }

  /**
   * Exchanges an (external) access token for a new (internal) one.
   *
   * @param subjectToken The access token to exchange.
   * @param clientId The client ID.
   * @param subjectTokenType (optional) The subject token type, defaults to [ACCESS_TOKEN_TYPE].
   * @param clientSecret (optional) The client secret.
   * @param requestedClientScope (optional) The requested client scope.
   * @param clientAssertionType (optional) The client assertion type, usually [org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT]
   * @param clientAssertion (optional) The signed JWT
   * @return A [KeycloakResponse] containing an [AccessTokenResponse].
   */
  @Suppress("LongParameterList", "kotlin:S107")
  fun tokenExchange(
      clientId: String,
      subjectToken: String,
      subjectTokenType: String = JWT_TOKEN_TYPE,
      clientSecret: String? = null,
      requestedClientScope: String? = null,
      requestedTokenType: String = REFRESH_TOKEN_TYPE,
      clientAssertionType: String? = null,
      clientAssertion: String? = null,
      dPoPToken: String? = null,
      audience: String? = null,
  ): KeycloakResponse<AccessTokenResponse> {
    val request =
        post(uriBuilder().tokenUrl())
            .addFormHeaders()
            .addParameter(CLIENT_ID, clientId)
            .addParameter(GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE)
            .addParameter(SUBJECT_TOKEN, subjectToken)
            .addParameter(SUBJECT_TOKEN_TYPE, subjectTokenType)
            .addParameter(REQUESTED_TOKEN_TYPE, requestedTokenType)

    if (requestedClientScope != null) {
      request.addParameter(SCOPE, requestedClientScope)
    }

    if (dPoPToken != null) {
      request.addHeader(DPOP_HTTP_HEADER, dPoPToken)
    }

    if (clientSecret != null) {
      request.addParameter(CLIENT_SECRET, clientSecret)
    }

    if (clientAssertionType != null && clientAssertion != null) {
      request.addParameter(CLIENT_ASSERTION_TYPE, clientAssertionType)
    }

    if (clientAssertion != null) {
      request.addParameter(CLIENT_ASSERTION, clientAssertion)
    }

    if (audience != null) {
      request.addParameter(AUDIENCE, audience)
    }

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<AccessTokenResponse>()
  }

  /**
   * Logs out a user.
   *
   * @param realm The realm to log out from.
   */
  fun logout(realm: String) {
    val request = get(uriBuilder().tokenUrl(ZETA_REALM)).addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)

    createHttpClient().use { it.execute(request.build()) }
  }

  /**
   * Gets user information.
   *
   * @param realm The realm.
   * @param token The access token.
   * @param expectedStatusCode The expected status code.
   * @return A [KeycloakResponse] containing a [UserInfo].
   */
  fun getUserInfo(realm: String, token: String, expectedStatusCode: Int = SC_OK): KeycloakResponse<UserInfo> {
    val request = get(uriBuilder().userinfoUrl(realm)).addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$token")

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<UserInfo>()
  }

  /**
   * Create an initial access token (for client registration)
   *
   * https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_initial_access
   *
   * @param adminToken The access token of the keycloak admin user.
   * @return A [KeycloakResponse] containing a [ClientInitialAccessPresentation].
   */
  fun createInitialAccessToken(adminToken: String): KeycloakResponse<ClientInitialAccessPresentation> {
    val expiration = 5.minutes.inWholeSeconds.toInt()
    val body = ClientInitialAccessCreatePresentation(expiration, 1).toJSON()
    val request =
        post(uriBuilder().initialAccessTokenUrl())
            .addJsonHeaders()
            .addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$adminToken")
            // Important value, but not mentioned in documentation 🙄
            .addParameter(SCOPE, SCOPE_OPENID)
            .setEntity(StringEntity(body))

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<ClientInitialAccessPresentation>()
  }

  /**
   * Create a client (client registration) using a previously obtained initial access token
   *
   * https://www.keycloak.org/securing-apps/client-registration
   *
   * @param initialAccessToken The access token of the keycloak admin user.
   * @param expectedStatusCode The expected status code.
   * @return A [KeycloakResponse] containing a [ClientRepresentation].
   */
  fun createClientKeycloak(
      initialAccessToken: String,
      newClientId: String,
      expectedStatusCode: Int = SC_CREATED,
  ): KeycloakResponse<ClientRepresentation> {
    val body =
        ClientRepresentation()
            .apply {
              id = newClientId
              isFullScopeAllowed = true
              isPublicClient = true
              isBearerOnly = false
              description = ZETA_GUARD_CLIENT_NAME
              clientId = newClientId
              name = ZETA_GUARD_CLIENT_NAME
              isEnabled = true
              isStandardFlowEnabled = true
              clientAuthenticatorType = AUTH_TYPE_CLIENT_SECRET
              attributes =
                  mapOf(
                      REALM_CLIENT to "false",
                      STANDARD_TOKEN_EXCHANGE_ENABLED to "true",
                      STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED to SAME_SESSION.name,
                      ATTRIBUTE_ATTESTATION_STATE to ATTESTATION_STATE_VALID,
                  )
            }
            .toJSON()

    val request =
        post(uriBuilder().clientRegistrationKeycloakUrl())
            .addJsonHeaders()
            .addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$initialAccessToken")
            .setEntity(StringEntity(body))

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<ClientRepresentation>(expectedStatusCode)
  }

  /**
   * Create a client (client registration) using a previously obtained initial access token.
   *
   * The given JWKS is stored internally by Keycloak to verify the client_assertion JWT later on.
   *
   * https://www.keycloak.org/securing-apps/client-registration
   *
   * @param expectedStatusCode The expected status code.
   * @return A [KeycloakResponse] containing a [OIDCClientRepresentation].
   */
  fun createClientOIDC(webKeySet: JSONWebKeySet, expectedStatusCode: Int = SC_CREATED): KeycloakResponse<OIDCClientRepresentation> {
    val body =
        OIDCClientRepresentation()
            .apply {
              clientName = ZETA_GUARD_CLIENT_NAME

              // See https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#A_27799
              grantTypes = VALID_GRANT_TYPES
              tokenEndpointAuthMethod = PRIVATE_KEY_JWT // "none" -> public client
              tokenEndpointAuthSigningAlg = ES256
              //          dpopBoundAccessTokens = true
              jwks = webKeySet
              responseTypes = listOf(OIDCResponseType.TOKEN) // DPoPUtil.DPOP_TOKEN_TYPE
            }
            .toJSON()

    val request = post(uriBuilder().clientRegistrationOIDCUrl()).addJsonHeaders().setEntity(StringEntity(body, Charsets.UTF_8))

    return createHttpClient().use { it.execute(request.build()) }.mapJSONResponse<OIDCClientRepresentation>(expectedStatusCode)
  }

  /**
   * Maps an [HttpResponse] to an [Either] of [KeycloakError] or [KeycloakSuccessResponse].
   *
   * @param T The type of the success response.
   * @param expectedStatusCode The expected status code.
   * @return An [Either] containing a [KeycloakError] or a [KeycloakSuccessResponse] with a [T].
   */
  inline fun <reified T> HttpResponse.mapJSONResponse(expectedStatusCode: Int = SC_OK): KeycloakResponse<T> =
      if (this.statusLine.statusCode != expectedStatusCode) {
        mapError()
      } else {
        val clazz = T::class.java
        val body = `as`<T>()

        body
            .map { KeycloakSuccessResponse(it) }
            .mapLeft { KeycloakError(it.message(), "Could not create ${clazz.simpleName} from " + asString(), this.statusLine.statusCode) }
      }

  fun HttpResponse.mapError(): Either<KeycloakError, Nothing> =
      asError().mapLeft { KeycloakError(it.message(), asString(), this.statusLine.statusCode) }.merge().left()

  /**
   * Maps an [HttpResponse] to an [Either] of [KeycloakError] or [KeycloakSuccessResponse].
   *
   * @param expectedStatusCode The expected status code.
   * @return An [Either] containing a [KeycloakError] or a [KeycloakSuccessResponse] containing the response body string
   */
  fun HttpResponse.mapStringResponse(expectedStatusCode: Int = SC_OK): KeycloakResponse<String> =
      if (this.statusLine.statusCode != expectedStatusCode) {
        mapError()
      } else {
        KeycloakSuccessResponse(asString()).right()
      }

  /**
   * Deserializes a [HttpResponse] to an object of type [T].
   *
   * @param T The type to deserialize to.
   * @return An [Either] containing a [Throwable] or an object of type [T].
   */
  inline fun <reified T> HttpResponse.`as`(): Either<Throwable, T> = Either.catch { ObjectMapper().readValue(asString(), T::class.java) }

  /**
   * Deserializes a [HttpResponse] to a [KeycloakError] in case of an error.
   *
   * @return An [Either] containing a [Throwable] or a [KeycloakError].
   */
  fun HttpResponse.asError(): Either<Throwable, KeycloakError> = `as`<KeycloakError>().map { it.apply { statusCode = statusLine.statusCode } }

  /**
   * Buffers [HttpResponse] body as a string.
   *
   * @return The response as a string.
   */
  fun HttpResponse.asString(): String {
    if (currentBody == null) {
      currentBody = entity.content.bufferedReader().use(BufferedReader::readText)
    }

    return currentBody ?: ""
  }

  /**
   * Create HTTP client with SSL (PKIX) and hostname checks disabled if needed.
   *
   * Also reset cached body for every request
   */
  fun createHttpClient(): CloseableHttpClient {
    val httpClientBuilder = HttpClients.custom()

    if (scheme == "https") {
      httpClientBuilder
          .setSSLContext(SSLContextBuilder().loadTrustMaterial(null, TrustAllStrategy.INSTANCE).build())
          .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
    }

    currentBody = null

    return httpClientBuilder.build()
  }
}

private fun RequestBuilder.addJsonHeaders(): RequestBuilder =
    addHeader(CONTENT_TYPE, APPLICATION_JSON.mimeType).addHeader(ACCEPT, APPLICATION_JSON.mimeType)

private fun RequestBuilder.addFormHeaders(): RequestBuilder =
    addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType).addHeader(ACCEPT, APPLICATION_JSON.mimeType)
