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

import de.gematik.zeta.zetaguard.keycloak.commons.ClientAssertionTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.BIND_EMAIL_VERIFY_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.CHALLENGE_TYPE_EMAIL_OTP
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLIENTS_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_RESEND_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.IDENTITY_EMAIL_VERIFY_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import java.net.URI
import java.net.URLEncoder
import java.util.Base64
import java.nio.charset.StandardCharsets.UTF_8
import java.security.cert.X509Certificate
import java.util.UUID
import org.apache.http.HttpResponse
import org.apache.http.HttpHeaders.CONTENT_TYPE
import org.apache.http.HttpHeaders.LOCATION
import org.apache.http.HttpStatus.SC_CREATED
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.client.utils.URLEncodedUtils
import org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED
import org.apache.http.entity.ContentType.APPLICATION_JSON
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.HttpClientBuilder
import org.apache.http.util.EntityUtils
import org.keycloak.OAuth2Constants.AUDIENCE
import org.keycloak.OAuth2Constants.AUTHORIZATION_CODE
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.OAuth2Constants.CLIENT_ID
import org.keycloak.OAuth2Constants.CODE_CHALLENGE
import org.keycloak.OAuth2Constants.CODE_CHALLENGE_METHOD
import org.keycloak.OAuth2Constants.CODE_VERIFIER
import org.keycloak.OAuth2Constants.EXPIRES_IN
import org.keycloak.OAuth2Constants.DPOP_HTTP_HEADER
import org.keycloak.OAuth2Constants.GRANT_TYPE
import org.keycloak.OAuth2Constants.PKCE_METHOD_S256
import org.keycloak.OAuth2Constants.REDIRECT_URI
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.RESOURCE
import org.keycloak.OAuth2Constants.RESPONSE_TYPE
import org.keycloak.OAuth2Constants.SCOPE
import org.keycloak.OAuth2Constants.STATE
import org.keycloak.protocol.oidc.OIDCLoginProtocol.CODE_PARAM
import org.keycloak.protocol.oidc.OIDCLoginProtocol.REQUEST_URI_PARAM
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.util.JsonSerialization

// Registered as the client's redirect_uris by DCR callers; SekIDPIdentityProvider checks oidc_redirect_uri against that list too.
const val SEKIDP_OUTER_REDIRECT_URI = "https://zeta-it.invalid/cb/app"
const val SEKIDP_OIDC_REDIRECT_URI = "https://zeta-it.invalid/cb/oidc"

private const val IDP_ISS = "http://gsi-server:8085"
private const val SEKIDP_SCOPE = "openid"
private const val TARGET_RESOURCE = "https://example.com/testresource"
private const val SEKIDP_ALIAS = "zeta-sekidp-oidc"
private const val OIDC_REDIRECT_URI_PARAM = "oidc_redirect_uri"
private const val IDP_ISS_PARAM = "idp_iss"
private const val USER_ID_PARAM = "user_id"
private const val MAX_REDIRECTS = 3
private const val SSL_CLIENT_CERT_HEADER = "ssl-client-cert"

/** A DCR-registered client together with the key its `private_key_jwt` client assertions are signed with. */
data class RegisteredClient(val representation: OIDCClientRepresentation, val key: ClientAssertionTokenGenerator) {
  val clientId: String
    get() = representation.clientId
}

data class PushedAuthorizationResponse(val requestUri: String, val expiresIn: Int)

data class TokenResult(val statusCode: Int, val body: String) {
  val response: AccessTokenResponse by lazy { JsonSerialization.mapper.readValue(body, AccessTokenResponse::class.java) }
}

private const val HEADER_ZETA_CLIENT_DATA = "zeta-client-data"

class SekIdpFlowClient(kcHost: String, kcPort: Int, gsiHost: String, gsiPort: Int) {
  private val kcBaseUrl = "http://$kcHost:$kcPort"
  private val gsiServerBaseUrl = "http://$gsiHost:$gsiPort"
  private val realmUrl = "$kcBaseUrl/realms/$ZETA_REALM"
  private val gsiServerContainerHost = URI(IDP_ISS).host
  private val httpClient = HttpClientBuilder.create().disableRedirectHandling().disableCookieManagement().build()

  fun parParameters(client: RegisteredClient, codeChallenge: String, state: String): Map<String, String> =
      mapOf(
          CLIENT_ID to client.clientId,
          CLIENT_ASSERTION_TYPE to CLIENT_ASSERTION_TYPE_JWT,
          CLIENT_ASSERTION to clientAssertion(client),
          RESPONSE_TYPE to "code",
          REDIRECT_URI to SEKIDP_OUTER_REDIRECT_URI,
          OIDC_REDIRECT_URI_PARAM to SEKIDP_OIDC_REDIRECT_URI,
          IDP_ISS_PARAM to IDP_ISS,
          SCOPE to SEKIDP_SCOPE,
          RESOURCE to TARGET_RESOURCE,
          CODE_CHALLENGE to codeChallenge,
          CODE_CHALLENGE_METHOD to PKCE_METHOD_S256,
          STATE to state,
      )

  fun postPushedAuthorizationRequest(parameters: Map<String, String>): TokenResult {
    val request =
        RequestBuilder.post("$realmUrl/protocol/openid-connect/ext/par/request")
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            .apply { parameters.forEach(::addParameter) }
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  fun pushAuthorizationRequest(client: RegisteredClient, codeChallenge: String, state: String): PushedAuthorizationResponse {
    val (statusCode, body) = postPushedAuthorizationRequest(parParameters(client, codeChallenge, state))

    check(statusCode == SC_CREATED) { "Outer PAR failed: $statusCode $body" }

    val json = JsonSerialization.mapper.readTree(body)
    val requestUri = json.path(REQUEST_URI_PARAM).asText().ifBlank { error("Outer PAR response has no $REQUEST_URI_PARAM: $body") }

    return PushedAuthorizationResponse(requestUri, json.path(EXPIRES_IN).asInt())
  }

  fun authorize(requestUri: String, clientId: String): String {
    var request =
        RequestBuilder.get("$realmUrl/protocol/openid-connect/auth").addParameter(CLIENT_ID, clientId).addParameter(REQUEST_URI_PARAM, requestUri)

    repeat(MAX_REDIRECTS) {
      val location = httpClient.execute(request.build()).redirectLocation("/authorize")

      if (URI(location).host == gsiServerContainerHost) {
        return location.queryParam(REQUEST_URI_PARAM)
      }

      request = RequestBuilder.get(location)
    }

    error("Did not reach $IDP_ISS within $MAX_REDIRECTS redirects from /authorize")
  }

  fun sekIdpLogin(innerRequestUri: String, kvnr: String): Pair<String, String> {
    val request = RequestBuilder.get("$gsiServerBaseUrl/auth").addParameter(REQUEST_URI_PARAM, innerRequestUri).addParameter(USER_ID_PARAM, kvnr).build()

    val location = httpClient.execute(request).redirectLocation("SekIDP /auth")

    return location.queryParam(CODE_PARAM) to location.queryParam(STATE)
  }

  /** Cookie-free (`state_as`): the broker callback does not need the `AUTH_SESSION_ID` from [authorize]. */
  fun relayBrokerCallback(code: String, state: String): String {
    val request = RequestBuilder.get("$realmUrl/broker/$SEKIDP_ALIAS/endpoint").addParameter(CODE_PARAM, code).addParameter(STATE, state).build()

    return httpClient.execute(request).redirectLocation("broker endpoint").queryParam(CODE_PARAM)
  }

  fun exchangeCodeForToken(client: RegisteredClient, code: String, codeVerifier: String): TokenResult {
    val tokenUrl = "$realmUrl/protocol/openid-connect/token"
    val request =
        RequestBuilder.post(tokenUrl)
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            .addHeader(DPOP_HTTP_HEADER, generateDPoPToken(endpointURL = URI(tokenUrl), accessToken = ""))
            .addParameter(GRANT_TYPE, AUTHORIZATION_CODE)
            .addParameter(CODE_PARAM, code)
            .addParameter(REDIRECT_URI, SEKIDP_OUTER_REDIRECT_URI)
            .addParameter(CODE_VERIFIER, codeVerifier)
            .addParameter(AUDIENCE, TARGET_RESOURCE)
            .addParameter(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT)
            .addParameter(CLIENT_ASSERTION, clientAssertion(client))
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  fun refreshToken(client: RegisteredClient, refreshToken: String): TokenResult {
    val tokenUrl = "$realmUrl/protocol/openid-connect/token"
    val request =
        RequestBuilder.post(tokenUrl)
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            .addHeader(DPOP_HTTP_HEADER, generateDPoPToken(endpointURL = URI(tokenUrl), accessToken = ""))
            .addParameter(GRANT_TYPE, REFRESH_TOKEN)
            .addParameter(REFRESH_TOKEN, refreshToken)
            .addParameter(CLIENT_ASSERTION_TYPE, CLIENT_ASSERTION_TYPE_JWT)
            .addParameter(CLIENT_ASSERTION, clientAssertion(client))
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  fun bindEmail(accessToken: String, email: String): TokenResult = postBinding(BIND_EMAIL_PATH, accessToken, "email" to email)

  fun verifyEmailOtp(accessToken: String, code: String): TokenResult = postBinding(BIND_EMAIL_VERIFY_PATH, accessToken, "code" to code)

  /**
   * `GET zeta/userinfo/email` as a resource server. The client certificate travels URL-encoded in `ssl-client-cert`, the
   * way the ingress forwards it (Keycloak's `nginx` x509cert-lookup provider).
   */
  fun userInfoEmail(id: String?, clientCertificate: X509Certificate?): TokenResult {
    val request = RequestBuilder.get("$realmUrl/zeta/userinfo/email")

    id?.let { request.addParameter("id", it) }
    clientCertificate?.let { request.addHeader(SSL_CLIENT_CERT_HEADER, URLEncoder.encode(it.toPem(), UTF_8)) }

    val response = httpClient.execute(request.build())

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  /**
   * `POST /zeta/identity/email` the way it arrives behind the PEP: no bearer token, the caller is the `client_id` of the client data
   * payload the PEP forwards in `ZETA-Access-Token-Content` (null = header omitted).
   */
  fun changeEmail(accessToken: String?, newEmail: String): TokenResult {
    val request =
        RequestBuilder.post("$realmUrl/zeta/$IDENTITY_EMAIL_PATH")
            .addHeader(CONTENT_TYPE, APPLICATION_JSON.mimeType)
            .apply { accessToken?.let { addHeader(HEADER_ZETA_CLIENT_DATA, clientData(it)) } }
            .setEntity(StringEntity(JsonSerialization.writeValueAsString(mapOf("new_email" to newEmail)), APPLICATION_JSON))
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  fun verifyEmailChangeOtp(accessToken: String?, code: String): TokenResult = postBehindPep(IDENTITY_EMAIL_VERIFY_PATH, accessToken, "code" to code)

  fun resendEmailChangeOtp(accessToken: String?): TokenResult =
      postBehindPep(IDENTITY_EMAIL_RESEND_PATH, accessToken, "verify_type" to CHALLENGE_TYPE_EMAIL_OTP)

  /** `GET /zeta/clients` behind the PEP: the mobile clients of the caller's identity. */
  fun listClients(accessToken: String): TokenResult {
    val request = RequestBuilder.get("$realmUrl/zeta/$CLIENTS_PATH").addHeader(HEADER_ZETA_CLIENT_DATA, clientData(accessToken)).build()
    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  /** `DELETE /zeta/clients/{id}` behind the PEP (null = header omitted). */
  fun deleteClient(accessToken: String?, clientId: String): TokenResult {
    val request =
        RequestBuilder.delete("$realmUrl/zeta/$CLIENTS_PATH/${URLEncoder.encode(clientId, UTF_8)}")
            .apply { accessToken?.let { addHeader(HEADER_ZETA_CLIENT_DATA, clientData(it)) } }
            .build()
    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  private fun postBehindPep(path: String, accessToken: String?, param: Pair<String, String>): TokenResult {
    val request =
        RequestBuilder.post("$realmUrl/zeta/$path")
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            .apply { accessToken?.let { addHeader(HEADER_ZETA_CLIENT_DATA, clientData(it)) } }
            .addParameter(param.first, param.second)
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  /** The PEP forwards the authorized client's data (client-data.yaml) as Base64-URL-encoded JSON. */
  private fun clientData(accessToken: String): String {
    val token = accessToken.toAccessToken()
    val json =
        JsonSerialization.writeValueAsString(
            mapOf(
                "client_id" to token.issuedFor,
                "product_id" to token.otherClaims["product_id"],
                "product_version" to token.otherClaims["product_version"],
                "platform" to token.otherClaims["platform"],
            )
        )
    return Base64.getUrlEncoder().encodeToString(json.toByteArray())
  }

  private fun postBinding(path: String, accessToken: String, param: Pair<String, String>): TokenResult {
    val url = "$realmUrl/zeta/$path"
    val request =
        RequestBuilder.post(url)
            .addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
            // behind the PEP: no bearer token, the caller arrives as client data (the PEP verified token, scope and DPoP)
            .addHeader(HEADER_ZETA_CLIENT_DATA, clientData(accessToken))
            .addParameter(param.first, param.second)
            .build()

    val response = httpClient.execute(request)

    return TokenResult(response.statusLine.statusCode, response.bodyOrEmpty())
  }

  private fun clientAssertion(client: RegisteredClient): String =
      client.key.generateClientAssertion(
          clientId = client.clientId,
          audiences = client.representation.registrationAccessToken.toAccessToken().audience.toList(),
          nonceString = UUID.randomUUID().toString(),
          otherClaims = emptyMap(),
      )

  private fun HttpResponse.redirectLocation(endpoint: String): String =
      checkNotNull(getFirstHeader(LOCATION)?.value) { "$endpoint: expected a redirect, got ${statusLine.statusCode}: ${bodyOrEmpty()}" }

  private fun HttpResponse.bodyOrEmpty(): String = entity?.let { EntityUtils.toString(it, UTF_8) } ?: ""

  private fun String.queryParam(name: String): String =
      URLEncodedUtils.parse(URI(this), UTF_8).firstOrNull { it.name == name }?.value ?: error("Missing query parameter »$name« in $this")
}
