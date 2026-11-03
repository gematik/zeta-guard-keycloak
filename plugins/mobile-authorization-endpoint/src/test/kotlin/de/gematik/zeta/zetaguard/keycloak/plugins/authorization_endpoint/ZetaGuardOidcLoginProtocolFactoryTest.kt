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
package de.gematik.zeta.zetaguard.keycloak.plugins.authorization_endpoint

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.mockk
import org.keycloak.events.EventBuilder
import org.keycloak.models.KeycloakSession
import org.keycloak.protocol.LoginProtocolSpi
import org.keycloak.protocol.oidc.OIDCLoginProtocol
import org.keycloak.protocol.oidc.OIDCLoginProtocolFactory

class ZetaGuardOidcLoginProtocolFactoryTest : FunSpec() {

  init {
    test("registers under Keycloak's own openid-connect id") {
      ZetaGuardOidcLoginProtocolFactory().id shouldBe OIDCLoginProtocol.LOGIN_PROTOCOL
    }

    test("outranks the stock factory of the same id, which is how Keycloak picks among duplicates") {
      ZetaGuardOidcLoginProtocolFactory().order() shouldBeGreaterThan OIDCLoginProtocolFactory().order()
    }

    test("serves the protocol through its own resource, whose /auth is the zeta endpoint") {
      val session = mockk<KeycloakSession>(relaxed = true)
      val event = mockk<EventBuilder>(relaxed = true)

      val service = ZetaGuardOidcLoginProtocolFactory().createProtocolEndpoint(session, event)

      service.shouldBeInstanceOf<ZetaGuardOidcLoginProtocolService>().auth().shouldBeInstanceOf<ZetaGuardAuthorizationEndpoint>()
    }

    test("is a login protocol SPI provider, so the META-INF registration is picked up") {
      LoginProtocolSpi().providerFactoryClass.isAssignableFrom(ZetaGuardOidcLoginProtocolFactory::class.java) shouldBe true
    }
  }
}
