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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_USER
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.generateRSAKeys
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.KeyPair
import org.keycloak.OAuth2Constants
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.common.util.Time
import org.keycloak.crypto.AsymmetricSignatureSignerContext
import org.keycloak.jose.jwk.JWK
import org.keycloak.jose.jws.JWSBuilder
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.representations.JsonWebToken
import org.keycloak.representations.oidc.OIDCClientRepresentation
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_INITIAL_ACCESS_TOKEN
import org.keycloak.services.clientregistration.ClientRegistrationTokenUtils.TYPE_REGISTRATION_ACCESS_TOKEN
import org.keycloak.util.JWKSUtils.getKeyWrapper
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

@Order(1)
class ClientRegistrationIT : FunSpec() {
    init {
        val (keypair, jwk, webKeySet) = generateRSAKeys()

        test(
            "Get initial access token, register client using Keycloak method and run token exchange"
        ) {
            val keycloakWebClient = KeycloakWebClient()
            val initialAccessToken = createInitialAccessToken(keycloakWebClient)
            val newClientId = KeycloakModelUtils.generateId()
            val registerClientResponse =
                keycloakWebClient
                    .createClientKeycloak(initialAccessToken, newClientId)
                    .shouldBeRight()
                    .reponseObject
            val registrationAccessToken =
                registerClientResponse.registrationAccessToken.toAccessToken()

            registrationAccessToken.type shouldBe TYPE_REGISTRATION_ACCESS_TOKEN
            registrationAccessToken.issuer shouldContain ZETA_REALM

            testExchangeToken(keycloakWebClient, newClientId)
        }

        test("Get initial access token, register client using OIDC method and run token exchange") {
            val keycloakWebClient = KeycloakWebClient()
            val initialAccessToken = createInitialAccessToken(keycloakWebClient)
            val registerClientResponse =
                keycloakWebClient
                    .createClientOIDC(webKeySet, initialAccessToken)
                    .shouldBeRight()
                    .reponseObject
            val jws = createJWSForTokenExchange(registerClientResponse, jwk, keypair)

            testExchangeToken(
                keycloakWebClient,
                registerClientResponse.clientId,
                clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
                clientAssertion = jws,
            )
        }

        test(
            "Register client for token exchange using OIDC without access token and run token exchange"
        ) {
            val keycloakWebClient = KeycloakWebClient()
            val registerClientResponse =
                keycloakWebClient.createClientOIDC(webKeySet).shouldBeRight().reponseObject
            val jws = createJWSForTokenExchange(registerClientResponse, jwk, keypair)

            testExchangeToken(
                keycloakWebClient,
                registerClientResponse.clientId,
                clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
                clientAssertion = jws,
            )
        }
    }

    private fun createJWSForTokenExchange(
        client: OIDCClientRepresentation,
        jwk: JWK,
        keypair: KeyPair,
    ): String {
        val registrationAccessToken =
            client.registrationAccessToken.toAccessToken().also {
                it.type shouldBe TYPE_REGISTRATION_ACCESS_TOKEN
                it.issuer shouldContain ZETA_REALM
            }
        val key = getKeyWrapper(jwk).apply { privateKey = keypair.private }
        val signer = AsymmetricSignatureSignerContext(key)
        return JWSBuilder()
            .type(OAuth2Constants.JWT)
            .jsonContent(
                generateJsonWebToken(
                    registrationAccessToken.id,
                    client.clientId,
                    registrationAccessToken.issuer,
                )
            )
            .sign(signer)
    }
}

private fun generateJsonWebToken(kid: String, clientId: String, issuer: String) =
    JsonWebToken().apply {
        id(kid)
        type(TOKEN_TYPE_BEARER)
        issuer(clientId)
        subject(clientId)
        audience(issuer)
        exp(Time.currentTime() + 300000L)
        issuedNow()
    }

fun createInitialAccessToken(client: KeycloakWebClient): String {
    val accessTokenResponse =
        client
            .login(
                realm = ADMIN_REALM,
                client = ADMIN_CLIENT,
                user = ADMIN_USER,
                password = ADMIN_PASSWORD,
            )
            .shouldBeRight()
            .reponseObject

    val initialAccessTokenResponse = client.createInitialAccessToken(accessTokenResponse.token)
    val initialAccessToken = initialAccessTokenResponse.shouldBeRight().reponseObject.token
    val accessToken = initialAccessToken.toAccessToken()

    accessToken.type shouldBe TYPE_INITIAL_ACCESS_TOKEN
    accessToken.issuer shouldContain ZETA_REALM

    client.logout(ZETA_REALM)
    return initialAccessToken
}
