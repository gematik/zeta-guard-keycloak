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

import com.fasterxml.jackson.annotation.JsonInclude.Include.NON_NULL
import com.fasterxml.jackson.databind.ObjectMapper
import org.keycloak.TokenVerifier
import org.keycloak.admin.client.Keycloak
import org.keycloak.common.util.Base64Url
import org.keycloak.constants.ServiceUrlConstants.ACCOUNT_SERVICE_PATH
import org.keycloak.constants.ServiceUrlConstants.AUTH_PATH
import org.keycloak.constants.ServiceUrlConstants.TOKEN_PATH
import org.keycloak.constants.ServiceUrlConstants.TOKEN_SERVICE_LOGOUT_PATH
import org.keycloak.representations.AccessToken

/**
 * Utility class for interacting with [Keycloak] admin cli and perform administrative operations
 * like user creation.
 *
 * @param hostname The hostname of the Keycloak server.
 * @param port The port of the Keycloak server.
 */
open class KeycloakAdminClient(hostname: String = KC_HOST, port: Int = KC_PORT) {
    @Suppress("HttpUrlsUsage") val keycloakUrl = "http://$hostname:$port"

    fun <R> withKeycloak(
        realm: String = ADMIN_REALM,
        username: String = ADMIN_USER,
        password: String = ADMIN_PASSWORD,
        clientId: String,
        block: Keycloak.() -> R,
    ): R {
        val keycloak =
            Keycloak.getInstance(
                keycloakUrl,
                realm,
                username,
                password,
                clientId,
                null,
                null,
                null,
                true,
                null,
            )

        with(keycloak) {
            use {
                return block()
            }
        }
    }

    fun tokenUrl(realm: String) = createUrl(TOKEN_PATH, realm)

    fun authUrl(realm: String) = createUrl(AUTH_PATH, realm)

    fun userinfoUrl(realm: String) = createUrl(USERINFO_PATH, realm)

    fun initialAccessTokenUrl(realm: String) = createUrl(INITIAL_ACCESS_TOKEN_PATH, realm)

    fun clientRegistrationKeycloakUrl(realm: String) =
        createUrl(KEYCLOAK_CLIENT_REGISTRATION_PATH, realm)

    fun clientRegistrationOIDCUrl(realm: String) = createUrl(OIDC_CLIENT_REGISTRATION_PATH, realm)

    fun accountConsoleUrl(realm: String) = createUrl(ACCOUNT_SERVICE_PATH, realm)

    fun logoutUrl(realm: String) = createUrl(TOKEN_SERVICE_LOGOUT_PATH, realm)

    fun createUrl(path: String, realm: String) =
        (keycloakUrl + path).replace("\\{realm-name}".toRegex(), realm)
}

fun String.toAccessToken(): AccessToken =
    TokenVerifier.create(this, AccessToken::class.java).getToken()

fun Any.toJSON(): String =
    ObjectMapper().setSerializationInclusion(NON_NULL).writeValueAsString(this)

fun Any.toBase64EncodedJSON(): String =
    Base64Url.encode(ObjectMapper().setSerializationInclusion(NON_NULL).writeValueAsBytes(this))
