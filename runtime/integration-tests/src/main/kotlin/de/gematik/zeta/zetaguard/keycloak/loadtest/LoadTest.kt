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
package de.gematik.zeta.zetaguard.keycloak.loadtest

import arrow.core.Either
import arrow.core.getOrElse
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.DPoPTokenGenerator.generateDPoPToken
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakSuccessResponse
import de.gematik.zeta.zetaguard.keycloak.commons.server.toBase64
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import org.keycloak.OAuth2Constants.CLIENT_ASSERTION_TYPE_JWT
import org.keycloak.representations.AccessTokenResponse
import org.keycloak.representations.oidc.OIDCClientRepresentation

class LoadTest(index: Int) : AutoCloseable {
  private val smcb = SMCBTokenHelper(index)
  private val keycloakWebClient = KeycloakWebClient.instance()
  private val smcbTokenAudience = listOf(keycloakWebClient.uriBuilder().tokenUrl().toString())
  private val clientAssertionAudience = keycloakWebClient.uriBuilder().realmUrl().toString()

  init {
    // SMC-B tokens bind to the keys actually presented in the exchange: the registered client key and the DPoP key.
    smcb.smcbTokenGenerator.defaultClientKeyJkt = clientAssertionTokenGenerator.keys.jwkThumbPrint.toBase64()
    smcb.smcbTokenGenerator.defaultDpopKeyJkt = DPoPTokenGenerator.keys.jwkThumbPrint.toBase64()
  }

  fun registerClient() = keycloakWebClient.createClientOIDC(clientAssertionTokenGenerator.keys.jwks).getRight()

  fun tokenExchange(oidcClientResponse: OIDCClientRepresentation): AccessTokenResponse {
    val nonce = keycloakWebClient.getNonce().getRight()
    val jws = clientAssertionTokenGenerator.generateClientAssertion(oidcClientResponse, nonce)
    val smbcToken =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            subject = smcb.telematikId,
            audiences = smcbTokenAudience,
            issuer = oidcClientResponse.clientId,
            issuedFor = oidcClientResponse.clientId,
            certificateChain = listOf(smcb.leafCertificate),
        )
    val dPoPToken = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smbcToken)

    return keycloakWebClient
        .tokenExchange(
            subjectToken = smbcToken,
            clientId = oidcClientResponse.clientId,
            requestedClientScope = CLIENT_B_SCOPE,
            clientAssertionType = CLIENT_ASSERTION_TYPE_JWT,
            clientAssertion = jws,
            dPoPToken = dPoPToken,
            audience = keycloakWebClient.uriBuilder().build().toString(),
        )
        .getRight()
  }

  fun refreshToken(accessTokenResponse: AccessTokenResponse, clientId: String): AccessTokenResponse {
    val nonce = keycloakWebClient.getNonce().getRight()
    val jws =
        clientAssertionTokenGenerator.generateClientAssertion(clientId = clientId, nonceString = nonce, audiences = listOf(clientAssertionAudience))
    val smbcToken =
        smcb.smcbTokenGenerator.generateSMCBToken(
            nonceString = nonce,
            subject = smcb.telematikId,
            audiences = smcbTokenAudience,
            issuer = clientId,
            issuedFor = clientId,
            certificateChain = listOf(smcb.leafCertificate),
        )
    val dPoPToken = generateDPoPToken(endpointURL = keycloakWebClient.uriBuilder().tokenUrl(), accessToken = smbcToken)

    return keycloakWebClient.refreshToken(accessTokenResponse.refreshToken, jws, dPoPToken).getRight()
  }

  override fun close() {
    keycloakWebClient.close()
  }
}

private fun <T> Either<KeycloakError, KeycloakSuccessResponse<T>>.getRight() = getOrElse { throw RuntimeException(it.errorDescription) }.reponseObject
