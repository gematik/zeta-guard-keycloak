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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.proxy.MethodAugmenter
import de.gematik.zeta.zetaguard.keycloak.proxy.createProxy
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.types.shouldBeSameInstanceAs
import io.mockk.mockk
import java.lang.reflect.Method
import org.keycloak.events.EventBuilder
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.TokenManager

class ProxyTest : FunSpec() {
  val realm = mockk<RealmModel>(relaxed = true)
  val client = mockk<ClientModel>(relaxed = true)
  val event = mockk<EventBuilder>(relaxed = true)
  val session = mockk<KeycloakSession>(relaxed = true)
  val userSession = mockk<UserSessionModel>(relaxed = true)
  val clientSessionCtx = mockk<ClientSessionContext>(relaxed = true)

  init {
    val delegate = TokenManager()
    val builder = delegate.AccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx)

    test("Intercept method call") {
      val augmenter =
          object : MethodAugmenter<TokenManager> {
            override fun execute(delegate: TokenManager, method: Method, args: Array<out Any?>) = builder

            override fun isAugmentedMethod(method: Method) = method.name == "responseBuilder"
          }

      val proxy = createProxy(delegate, augmenter)

      proxy.responseBuilder(realm, client, event, session, userSession, clientSessionCtx) shouldBeSameInstanceAs builder
      proxy.responseBuilder(realm, client, event, session, userSession, clientSessionCtx) shouldBeSameInstanceAs builder
    }
  }
}
