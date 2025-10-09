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
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.ZETA_REALM
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import jakarta.security.enterprise.authentication.mechanism.http.openid.OpenIdConstant.OPENID_SCOPE
import jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN

@Order(1)
class UserInfoIT : FunSpec() {
    init {
        test("Get user info without openid scope fails") {
            val keycloakWebClient = KeycloakWebClient()
            val accessTokenResponse =
                keycloakWebClient.login(client = CLIENT_A_ID).shouldBeRight().reponseObject

            keycloakWebClient.getUserInfo(ZETA_REALM, accessTokenResponse.token, SC_FORBIDDEN)
            keycloakWebClient.logout(ZETA_REALM)
        }

        test("Get user info") {
            val accessTokenResponse =
                KeycloakWebClient()
                    .login(client = CLIENT_A_ID, requestedClientScope = OPENID_SCOPE)
                    .shouldBeRight()
                    .reponseObject
            val userInfo =
                KeycloakWebClient()
                    .getUserInfo(ZETA_REALM, accessTokenResponse.token)
                    .shouldBeRight()
                    .reponseObject

            userInfo.email shouldBe "user1@foo.bar.com"
            userInfo.preferredUsername shouldBe "user1"
            KeycloakWebClient().logout(ZETA_REALM)
        }
    }
}
