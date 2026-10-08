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
package de.gematik.zeta.zetaguard.keycloak.plugins.client_auth

import jakarta.ws.rs.core.Response
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException
import org.keycloak.TokenVerifier
import org.keycloak.authentication.AuthenticationFlowError
import org.keycloak.authentication.ClientAuthenticationFlowContext
import org.keycloak.authentication.authenticators.client.ClientAuthUtil
import org.keycloak.authentication.authenticators.client.JWTClientAuthenticator
import org.keycloak.representations.JsonWebToken

/** Extends the standard JWT client authenticator with typ=JWT header validation according to A_25338-01. */
class ZetaGuardJWTClientAuthenticator : JWTClientAuthenticator() {

  override fun authenticateClient(context: ClientAuthenticationFlowContext) {
    val clientAssertion = context.httpRequest.decodedFormParameters.getFirst(OAuth2Constants.CLIENT_ASSERTION)

    if (clientAssertion != null) {
      val header = TokenVerifier.create(clientAssertion, JsonWebToken::class.java).header
      if (header.type != OAuth2Constants.JWT) {
        val response =
            ClientAuthUtil.errorResponse(
                Response.Status.BAD_REQUEST.statusCode,
                OAuthErrorException.INVALID_REQUEST,
                "Invalid client assertion token type: »${header.type}«",
            )
        context.failure(AuthenticationFlowError.INVALID_CLIENT_CREDENTIALS, response)
        return
      }
    }

    super.authenticateClient(context)
  }

  override fun getId(): String = PROVIDER_ID

  override fun order(): Int = 30
}
