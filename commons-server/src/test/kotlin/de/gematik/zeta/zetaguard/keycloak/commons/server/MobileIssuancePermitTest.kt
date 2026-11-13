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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.mockk.every
import io.mockk.mockk
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession

class MobileIssuancePermitTest :
    FunSpec({
      test("no permit without the mobile PDP gate") {
        requestSession().isMobileIssuancePermitted(client("mobile-client-uuid")).shouldBeFalse()
      }

      test("the permit applies to the client it was granted to") {
        val session = requestSession()
        val client = client("mobile-client-uuid")

        session.permitMobileIssuance(client)

        session.isMobileIssuancePermitted(client).shouldBeTrue()
      }

      // Shared SSO session: a gate decision for one client must not let another client mint a KVNR token
      test("the permit does not apply to another client") {
        val session = requestSession()

        session.permitMobileIssuance(client("mobile-client-uuid"))

        session.isMobileIssuancePermitted(client("other-client-uuid")).shouldBeFalse()
      }
    })

/** [KeycloakSession] whose attributes behave like the real request-scoped ones */
private fun requestSession(): KeycloakSession {
  val attributes = mutableMapOf<String, Any>()
  val session = mockk<KeycloakSession>()
  every { session.setAttribute(any(), any()) } answers { attributes[firstArg()] = secondArg() }
  every { session.getAttribute(any(), String::class.java) } answers { attributes[firstArg()] as String? }
  return session
}

private fun client(id: String): ClientModel = mockk<ClientModel>().also { every { it.id } returns id }
