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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SECRET
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_ZETA
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SMCB_ISSUER
import de.gematik.zeta.zetaguard.keycloak.commons.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import de.gematik.zeta.zetaguard.keycloak.commons.toBase64EncodedJSON
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.keycloak.OAuth2Constants.JWT_TOKEN_TYPE
import org.keycloak.jose.jws.Algorithm.RS256
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.representations.JsonWebToken
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

val SIGNATURE =
    """sHewe6f5zk_EslSVtectqb_91U_6YpYhQoQhWNFwLINJd3ryrKNaLOeB196x5fbAfFGSk-Exa9D24K64xzETnoKrXQRrRKi4sSJGxDqtXbkmbx
r-fJvyB3Ay_0_lCZAUPNEYH2Sx5caClRnJy60eeKt3pm4JmV5nLFXh-DOYEDc5r1NGcl1bwCt70pQJ1aKlMaiUDuC5N8CXSAuUdRc1IWzB324QN
BglW4qpUY2anp-j23bnJBhLmYgVeKa_RBksJ1-jSgwODeuO1gIR96qqc7SqjzQVgteGumr5zfR3qc5GAGGBIxYX3Jndr4lqcW2-mYffDwp7fWf4
a5FJ5wgUuw"""
        .lines()
        .joinToString("")

val ACCESS_TOKEN =
    """
eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJXdVo4bFJodHZvb1lxeHExU3A3SHM5ZmU4b2FFSFV6RGNFckRYOUJ2OWhNIn0
.eyJleHAiOjE3NTg2MTExNjgsImlhdCI6MTc1ODYxMDg2OCwianRpIjoib25ydHJvOjU5OWNmYjAyLTI0YTktNDViZi0xNDRlLTZjNDg5YTYxMz
I2NSIsImlzcyI6Imh0dHA6Ly9sb2NhbGhvc3Q6MTgwODAvcmVhbG1zL3NtYy1iIiwiYXVkIjpbInJlcXVlc3Rlci1jbGllbnQiLCJhY2NvdW50I
l0sInN1YiI6ImQwYWFjYzljLTJkOTMtNDM4YS1hNzAzLWI4Nzc4OTIxODNmOCIsInR5cCI6IkJlYXJlciIsImF6cCI6InNtYy1iLWNsaWVudCIs
InNpZCI6IjY5ZDgxODA4LTY2ZTYtNDlmMi04OWRiLTdiODBlOGU4OTlmYiIsImFjciI6IjEiLCJyZWFsbV9hY2Nlc3MiOnsicm9sZXMiOlsiZGV
mYXVsdC1yb2xlcy1zbWMtYiIsIm9mZmxpbmVfYWNjZXNzIiwidW1hX2F1dGhvcml6YXRpb24iXX0sInJlc291cmNlX2FjY2VzcyI6eyJhY2NvdW
50Ijp7InJvbGVzIjpbIm1hbmFnZS1hY2NvdW50IiwibWFuYWdlLWFjY291bnQtbGlua3MiLCJ2aWV3LXByb2ZpbGUiXX19LCJzY29wZSI6ImVtY
WlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVzZXIgRXh0ZXJuYWwiLCJwcmVmZXJyZWRfdXNlcm5hbWUiOiJ1c2Vy
IiwiZ2l2ZW5fbmFtZSI6IlVzZXIiLCJmYW1pbHlfbmFtZSI6IkV4dGVybmFsIiwiZW1haWwiOiJ1c2VyQGJhci5mb28uY29tIn0
.$SIGNATURE
"""
        .lines()
        .joinToString("")

val jwTokenHeader =
    JWSHeader(RS256, "JWT", "WuZ8lRhtvooYqxq1Sp7Hs9fe8oaEHUzDcErDX9Bv9hM").toBase64EncodedJSON()

val jwToken =
    JsonWebToken()
        .exp(1958610868) // exp
        .issuer(SMCB_ISSUER)
        .issuedNow() // iat
        .issuedFor(SMCB_ISSUER) // azp
        .id(SMCB_ISSUER) // jti
        .audience(CLIENT_B_ID) // aud
        .subject("user") // sub
        .type(TOKEN_TYPE_BEARER) // typ
        .toBase64EncodedJSON()

@Order(1)
class ExternalTokenExchangeIT : FunSpec() {
    init {
        test("External token exchange with access token") {
            val keycloakWebClient = KeycloakWebClient()
            testExchangeToken(keycloakWebClient, requestedClientScope = CLIENT_B_SCOPE)
        }

        test("External token exchange with plain JWT") {
            val newAccessTokenResponse =
                KeycloakWebClient()
                    .tokenExchange(
                        accessToken = "$jwTokenHeader.$jwToken.$SIGNATURE",
                        clientId = CLIENT_B_ID,
                        subjectTokenType = JWT_TOKEN_TYPE,
                        clientSecret = CLIENT_B_SECRET,
                        requestedClientScope = CLIENT_B_SCOPE,
                    )
                    .shouldBeRight()
                    .reponseObject
            newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER
            val newAccessToken = newAccessTokenResponse.token.toAccessToken()

            newAccessToken.issuer shouldContain ZETA_REALM
            newAccessToken.issuedFor shouldBe CLIENT_B_ID
            newAccessToken.audience shouldContain CLIENT_C_ID
        }
    }
}

fun testExchangeToken(
    keycloakWebClient: KeycloakWebClient,
    clientId: String = CLIENT_ZETA,
    clientAssertionType: String? = null,
    clientAssertion: String? = null,
    requestedClientScope: String? = null,
) {
    val newAccessTokenResponse =
        keycloakWebClient
            .tokenExchange(
                accessToken = ACCESS_TOKEN,
                clientId = clientId,
                subjectTokenType = JWT_TOKEN_TYPE,
                clientAssertionType = clientAssertionType,
                clientAssertion = clientAssertion,
                requestedClientScope = requestedClientScope, // Create "aud"ience claim in token
            )
            .shouldBeRight()
            .reponseObject
    newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER

    val newAccessToken = newAccessTokenResponse.token.toAccessToken()

    newAccessToken.issuer shouldContain ZETA_REALM
    newAccessToken.issuedFor shouldBe clientId

    if (requestedClientScope == CLIENT_B_SCOPE) {
        newAccessToken.audience shouldContain CLIENT_C_ID
    }
}
