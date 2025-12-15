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

import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_A_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_A_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_ID
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SCOPE
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_B_SECRET
import de.gematik.zeta.zetaguard.keycloak.commons.CLIENT_C_ID
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.toAccessToken
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldNotContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.keycloak.OAuth2Constants.ACCESS_TOKEN_TYPE
import org.keycloak.util.TokenUtil.TOKEN_TYPE_BEARER

@Order(1)
class InternalTokenExchangeIT : FunSpec() {
  init {
    test("Internal token exchange with explicit client scopes/audiences") {
      val keycloakWebClient = KeycloakWebClient()
      val accessTokenResponse = keycloakWebClient.login(client = CLIENT_A_ID, requestedClientScope = CLIENT_A_SCOPE).shouldBeRight().reponseObject

      accessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER

      val accessToken = accessTokenResponse.token.toAccessToken()

      accessToken.email shouldBe "user1@foo.bar.com"
      accessToken.audience shouldContain CLIENT_B_ID

      val newAccessTokenResponse =
          keycloakWebClient
              .tokenExchange(
                  CLIENT_B_ID,
                  accessTokenResponse.token,
                  clientSecret = CLIENT_B_SECRET,
                  requestedClientScope = CLIENT_B_SCOPE,
                  subjectTokenType = ACCESS_TOKEN_TYPE,
                  requestedTokenType = ACCESS_TOKEN_TYPE,
              )
              .shouldBeRight()
              .reponseObject
      newAccessTokenResponse.tokenType shouldBe TOKEN_TYPE_BEARER
      val newAccessToken = newAccessTokenResponse.token.toAccessToken()

      newAccessToken.email shouldBe "user1@foo.bar.com"
      newAccessToken.audience shouldContain CLIENT_C_ID

      keycloakWebClient.logout(ZETA_REALM)
    }

    test("Token exchange without client scopes/audiences") {
      val keycloakWebClient = KeycloakWebClient()
      val accessTokenResponse = keycloakWebClient.login(client = CLIENT_A_ID).shouldBeRight().reponseObject
      val accessToken = accessTokenResponse.token.toAccessToken()

      accessToken.email shouldBe "user1@foo.bar.com"
      accessToken.audience shouldNotContain CLIENT_B_ID

      keycloakWebClient
          .tokenExchange(
              CLIENT_B_ID,
              accessTokenResponse.token,
              clientSecret = CLIENT_B_SECRET,
              requestedClientScope = CLIENT_B_SCOPE,
              subjectTokenType = ACCESS_TOKEN_TYPE,
              requestedTokenType = ACCESS_TOKEN_TYPE,
          )
          .shouldBeLeft()
          .errorDescription shouldContain "Client is not within the token audience"
      keycloakWebClient.logout(ZETA_REALM)
    }
  }
}
