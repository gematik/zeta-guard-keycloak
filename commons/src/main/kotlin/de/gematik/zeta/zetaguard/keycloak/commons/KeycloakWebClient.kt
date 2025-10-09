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
import com.fasterxml.jackson.databind.ObjectMapper
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
import org.apache.http.entity.ContentType.APPLICATION_FORM_URLENCODED
import org.apache.http.entity.ContentType.APPLICATION_JSON
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.keycloak.OAuth2Constants.ACCESS_TOKEN_TYPE
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE
import org.keycloak.OAuth2Constants.CLIENT_ID
import org.keycloak.OAuth2Constants.CLIENT_SECRET
import org.keycloak.OAuth2Constants.GRANT_TYPE
import org.keycloak.OAuth2Constants.PASSWORD
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.REQUESTED_TOKEN_TYPE
import org.keycloak.OAuth2Constants.SCOPE
import org.keycloak.OAuth2Constants.SCOPE_OPENID
import org.keycloak.OAuth2Constants.SUBJECT_ISSUER
import org.keycloak.OAuth2Constants.SUBJECT_TOKEN
import org.keycloak.OAuth2Constants.SUBJECT_TOKEN_TYPE
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.OAuth2Constants.USERNAME
import org.keycloak.admin.client.resource.BearerAuthFilter.AUTH_HEADER_PREFIX
import org.keycloak.jose.jwk.JSONWebKeySet
import org.keycloak.models.Constants.REALM_CLIENT
import org.keycloak.models.utils.KeycloakModelUtils.AUTH_TYPE_CLIENT_SECRET
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

typealias KeycloakResponse<T> = Either<KeycloakErrorResponse, KeycloakSuccessResponse<T>>

/**
 * A web client for interacting with Keycloak.
 *
 * @param hostname The hostname of the Keycloak server.
 * @param port The port of the Keycloak server.
 */
class KeycloakWebClient(hostname: String = KC_HOST, port: Int = KC_PORT) :
    KeycloakAdminClient(hostname, port) {
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
            post(tokenUrl(realm))
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

        return createHttpClient()
            .use { it.execute(request.build()) }
            .mapResponse<AccessTokenResponse>()
    }

    /**
     * Exchanges an (external) access token for a new (internal) one.
     *
     * @param accessToken The access token to exchange.
     * @param clientId The client ID.
     * @param subjectTokenType (optional) The subject token type, defaults to [ACCESS_TOKEN_TYPE].
     * @param clientSecret (optional) The client secret.
     * @param requestedClientScope (optional) The requested client scope.
     * @param subjectIssuer (optional) The subject issuer.
     * @param clientAssertionType (optional) The client assertion type, usually
     *   [org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT]
     * @param clientAssertion (optional) The signed JWT
     * @return A [KeycloakResponse] containing an [AccessTokenResponse].
     */
    @Suppress("LongParameterList", "kotlin:S107")
    fun tokenExchange(
        accessToken: String,
        clientId: String,
        subjectTokenType: String = ACCESS_TOKEN_TYPE,
        clientSecret: String? = null,
        requestedClientScope: String? = null,
        subjectIssuer: String? = null,
        clientAssertionType: String? = null,
        clientAssertion: String? = null,
    ): KeycloakResponse<AccessTokenResponse> {
        val request =
            post(tokenUrl(ZETA_REALM))
                .addFormHeaders()
                .addParameter(CLIENT_ID, clientId)
                .addParameter(GRANT_TYPE, TOKEN_EXCHANGE_GRANT_TYPE)
                .addParameter(SUBJECT_TOKEN, accessToken)
                .addParameter(SUBJECT_TOKEN_TYPE, subjectTokenType)
                .addParameter(REQUESTED_TOKEN_TYPE, ACCESS_TOKEN_TYPE)

        if (requestedClientScope != null) {
            request.addParameter(SCOPE, requestedClientScope)
        }

        if (clientSecret != null) {
            request.addParameter(CLIENT_SECRET, clientSecret)
        }

        if (clientAssertionType != null) {
            request.addParameter(CLIENT_ASSERTION_TYPE, clientAssertionType)
        }

        if (clientAssertion != null) {
            request.addParameter(CLIENT_ASSERTION, clientAssertion)
        }

        if (subjectIssuer != null) {
            request.addParameter(SUBJECT_ISSUER, subjectIssuer)
        }

        return createHttpClient()
            .use { it.execute(request.build()) }
            .mapResponse<AccessTokenResponse>()
    }

    /**
     * Logs out a user.
     *
     * @param realm The realm to log out from.
     */
    fun logout(realm: String) {
        val request =
            get(tokenUrl(ZETA_REALM)).addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)

        createHttpClient().use { it.execute(request.build()) }
    }

    /**
     * Gets user information.
     *
     * @param realm The realm.
     * @param token The access token.
     * @param expectedStatusCode The expected status code.
     * @return An [KeycloakResponse] containing a [UserInfo].
     */
    fun getUserInfo(
        realm: String,
        token: String,
        expectedStatusCode: Int = SC_OK,
    ): KeycloakResponse<UserInfo> {
        val request = get(userinfoUrl(realm)).addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$token")

        return createHttpClient().use { it.execute(request.build()) }.mapResponse<UserInfo>()
    }

    /**
     * Create an initial access token (for client registration)
     *
     * https://www.keycloak.org/docs-api/latest/rest-api/index.html#_client_initial_access
     *
     * @param adminToken The access token of the keycloak admin user.
     * @return A [KeycloakResponse] containing a [ClientInitialAccessPresentation].
     */
    fun createInitialAccessToken(
        adminToken: String
    ): KeycloakResponse<ClientInitialAccessPresentation> {
        val body =
            ClientInitialAccessCreatePresentation(5.minutes.inWholeSeconds.toInt(), 1).toJSON()
        val request =
            post(initialAccessTokenUrl(ZETA_REALM))
                .addJsonHeaders()
                .addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$adminToken")
                // Important value, but not mentioned in documentation 🙄
                .addParameter(SCOPE, SCOPE_OPENID)
                .setEntity(StringEntity(body))

        return createHttpClient()
            .use { it.execute(request.build()) }
            .mapResponse<ClientInitialAccessPresentation>()
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
                            STANDARD_TOKEN_EXCHANGE_REFRESH_ENABLED to "true",
                        )
                }
                .toJSON()

        val request =
            post(clientRegistrationKeycloakUrl(ZETA_REALM))
                .addJsonHeaders()
                .addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$initialAccessToken")
                .setEntity(StringEntity(body))

        return createHttpClient()
            .use { it.execute(request.build()) }
            .mapResponse<ClientRepresentation>(expectedStatusCode)
    }

    /**
     * Create a client (client registration) using a previously obtained initial access token
     *
     * https://www.keycloak.org/securing-apps/client-registration
     *
     * @param initialAccessToken The access token of the keycloak admin user.
     * @param expectedStatusCode The expected status code.
     * @return A [KeycloakResponse] containing a [OIDCClientRepresentation].
     */
    fun createClientOIDC(
        webKeySet: JSONWebKeySet,
        initialAccessToken: String? = null,
        expectedStatusCode: Int = SC_CREATED,
    ): KeycloakResponse<OIDCClientRepresentation> {
        val body =
            OIDCClientRepresentation()
                .apply {
                    clientName = ZETA_GUARD_CLIENT_NAME
                    grantTypes = listOf(TOKEN_EXCHANGE_GRANT_TYPE, REFRESH_TOKEN)
                    tokenEndpointAuthMethod = PRIVATE_KEY_JWT
                    jwks = webKeySet
                    responseTypes = listOf(OIDCResponseType.TOKEN)
                }
                .toJSON()

        val request =
            post(clientRegistrationOIDCUrl(ZETA_REALM))
                .addJsonHeaders()
                .setEntity(StringEntity(body))

        if (initialAccessToken != null) {
            request.addHeader(AUTHORIZATION, "$AUTH_HEADER_PREFIX$initialAccessToken")
        }

        return createHttpClient()
            .use { it.execute(request.build()) }
            .mapResponse<OIDCClientRepresentation>(expectedStatusCode)
    }

    /**
     * Maps an [HttpResponse] to an [Either] of [KeycloakErrorResponse] or
     * [KeycloakSuccessResponse].
     *
     * @param T The type of the success response.
     * @param expectedStatusCode The expected status code.
     * @return An [Either] containing a [KeycloakErrorResponse] or a [KeycloakSuccessResponse] with
     *   a [T].
     */
    private inline fun <reified T> HttpResponse.mapResponse(
        expectedStatusCode: Int = SC_OK
    ): KeycloakResponse<T> =
        if (this.statusLine.statusCode != expectedStatusCode) {
            val error =
                asError().mapLeft { KeycloakErrorResponse(it.message(), asString()) }.merge()

            error.left()
        } else {
            val clazz = T::class.java
            val body = `as`<T>()

            body
                .map { KeycloakSuccessResponse(it) }
                .mapLeft {
                    KeycloakErrorResponse(
                        it.message(),
                        "Could not create ${clazz.simpleName} from " + asString(),
                    )
                }
        }

    /**
     * Deserializes a [HttpResponse] to an object of type [T].
     *
     * @param T The type to deserialize to.
     * @return An [Either] containing a [Throwable] or an object of type [T].
     */
    inline fun <reified T> HttpResponse.`as`(): Either<Throwable, T> =
        Either.catch { ObjectMapper().readValue(asString(), T::class.java) }

    /**
     * Deserializes a [HttpResponse] to a [KeycloakErrorResponse] in case of an error.
     *
     * @return An [Either] containing a [Throwable] or a [KeycloakErrorResponse].
     */
    fun HttpResponse.asError(): Either<Throwable, KeycloakErrorResponse> =
        `as`<KeycloakErrorResponse>()

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

    /** Rset cached body for everey request */
    private fun createHttpClient(): CloseableHttpClient =
        HttpClients.createDefault().also { currentBody = null }
}

/**
 * Gets the message of a [Throwable].
 *
 * @return The message of the [Throwable] or "<unknown eror>" if the message is null.
 */
private fun Throwable.message() = message ?: "<unknown eror>"

private fun RequestBuilder.addJsonHeaders(): RequestBuilder =
    addHeader(CONTENT_TYPE, APPLICATION_JSON.mimeType).addHeader(ACCEPT, APPLICATION_JSON.mimeType)

private fun RequestBuilder.addFormHeaders(): RequestBuilder =
    addHeader(CONTENT_TYPE, APPLICATION_FORM_URLENCODED.mimeType)
        .addHeader(ACCEPT, APPLICATION_JSON.mimeType)
