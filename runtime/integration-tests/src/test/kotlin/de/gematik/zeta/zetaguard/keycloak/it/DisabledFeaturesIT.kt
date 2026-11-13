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

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_A_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SECRET
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_A
import de.gematik.zeta.zetaguard.keycloak.commons.SCOPE_CLIENT_B
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.apache.http.HttpStatus.SC_BAD_REQUEST
import org.apache.http.HttpStatus.SC_NOT_FOUND
import org.apache.http.client.methods.RequestBuilder.get
import org.apache.http.client.methods.RequestBuilder.post
import org.apache.http.util.EntityUtils
import org.keycloak.OAuth2Constants.ACCESS_TOKEN_TYPE
import org.keycloak.OAuth2Constants.CIBA_GRANT_TYPE
import org.keycloak.OAuth2Constants.CLIENT_ID
import org.keycloak.OAuth2Constants.CLIENT_SECRET
import org.keycloak.OAuth2Constants.DEVICE_CODE_GRANT_TYPE
import org.keycloak.OAuth2Constants.GRANT_TYPE
import org.keycloak.OAuth2Constants.JWT_AUTHORIZATION_GRANT
import org.keycloak.OAuthErrorException.UNSUPPORTED_GRANT_TYPE

/** Keycloak features not used by 𝝵-Guard are disabled in the image via `KC_FEATURES_DISABLED`. */
class DisabledFeaturesIT : ZetaGuardFunSpecIT() {
  init {
    mapOf(
            "account" to { get(uri("/realms/{realm-name}/account")) },
            "account-api" to { get(uri("/realms/{realm-name}/account/v1/")) },
            "device-flow" to { post(uri("/realms/{realm-name}/device")) },
            "ciba" to { post(uri("/realms/{realm-name}/protocol/openid-connect/ext/ciba/auth")) },
            "authorization" to { get(uri("/realms/{realm-name}/.well-known/uma2-configuration")) },
        )
        .forEach { (feature, request) ->
          test("Endpoints of disabled feature '$feature' are not available") {
            keycloakWebClient.httpClient().execute(request().build()).use { it.statusLine.statusCode shouldBe SC_NOT_FOUND }
          }
        }

    // The UMA grant type is not bound to the feature "authorization" and its id can't be disabled via environment variable
    listOf(DEVICE_CODE_GRANT_TYPE, CIBA_GRANT_TYPE, JWT_AUTHORIZATION_GRANT).forEach { grantType ->
      test("Grant type '$grantType' of a disabled feature is not supported") {
        val request =
            post(keycloakWebClient.uriBuilder().tokenUrl())
                .addHeader("X-Forwarded-For", "127.0.0.1") // A_28828
                .addParameter(GRANT_TYPE, grantType)
                // Keycloak authenticates the client before checking the grant type
                .addParameter(CLIENT_ID, CLIENT_B_ID)
                .addParameter(CLIENT_SECRET, CLIENT_B_SECRET)
                .build()

        keycloakWebClient.httpClient().execute(request).use {
          it.statusLine.statusCode shouldBe SC_BAD_REQUEST
          EntityUtils.toString(it.entity) shouldContain UNSUPPORTED_GRANT_TYPE
        }
      }
    }

    // Keycloak's standard token exchange is disabled: an access token can't be exchanged into a token of another client
    test("Standard token exchange of an access token is rejected") {
      val accessToken = keycloakWebClient.login(client = CLIENT_A_ID, requestedClientScope = SCOPE_CLIENT_A).shouldBeRight().responseObject.token

      keycloakWebClient
          .tokenExchange(
              CLIENT_B_ID,
              accessToken,
              clientSecret = CLIENT_B_SECRET,
              requestedClientScope = SCOPE_CLIENT_B,
              subjectTokenType = ACCESS_TOKEN_TYPE,
              requestedTokenType = ACCESS_TOKEN_TYPE,
          )
          .shouldBeLeft()
          .errorDescription shouldContain "Subject token type »$ACCESS_TOKEN_TYPE« is not supported"

      keycloakWebClient.logout(ZETA_REALM)
    }
  }

  private fun uri(path: String) = keycloakWebClient.uriBuilder().createUri(path, ZETA_REALM)
}
