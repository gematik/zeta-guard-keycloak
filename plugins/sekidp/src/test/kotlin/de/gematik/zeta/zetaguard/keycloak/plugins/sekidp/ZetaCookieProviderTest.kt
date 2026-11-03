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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.cookie.CookieProvider
import org.keycloak.cookie.CookieType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.SingleUseObjectProvider

private const val STATE_AS = "state-as-minted-by-the-guard"

/** What the mapping holds for [STATE_AS]. */
private const val MAPPED_AUTH_SESSION_ID = "signed-root-session-from-the-mapping.node1"

/** What Keycloak's default provider answers for AUTH_SESSION_ID: the cookie the device sent along. */
private const val DEFAULT_PROVIDER_AUTH_SESSION_ID = "root-session-from-the-default-provider.node1"

/** The cookie provider under test. It answers `AUTH_SESSION_ID` from the `state_as` mapping and delegates every other cookie to the default provider. */
class ZetaCookieProviderTest : ZetaGuardFunSpec() {

  /** Keycloak's default cookie provider. */
  private lateinit var delegate: CookieProvider

  /** The request's session: the Redirection Endpoint attaches `state_as` to it, the mapping lives in its single-use store. */
  private lateinit var session: KeycloakSession

  private lateinit var provider: ZetaCookieProvider

  init {
    beforeEach {
      delegate = mockk(relaxed = true) { every { get(CookieType.AUTH_SESSION_ID) } returns DEFAULT_PROVIDER_AUTH_SESSION_ID }

      val singleUse =
          mockk<SingleUseObjectProvider> {
            every { this@mockk[any()] } answers { if (firstArg<String>() == "zeta-state-as:$STATE_AS") mapOf("auth_session_id" to MAPPED_AUTH_SESSION_ID) else null }
          }
      val attributes = mutableMapOf<String, Any>()
      session = mockk {
        every { singleUseObjects() } returns singleUse
        every { setAttribute(any(), any()) } answers { attributes[firstArg()] = secondArg() }
        every { getAttribute(any(), String::class.java) } answers { attributes[firstArg()] as String? }
      }

      provider = ZetaCookieProvider(session, delegate)
    }

    context("without a state_as handed over the default provider answers") {
      test("no state_as, so AUTH_SESSION_ID too comes from the default provider, not the mapping") {
        provider.get(CookieType.AUTH_SESSION_ID) shouldBe DEFAULT_PROVIDER_AUTH_SESSION_ID
      }
    }

    context("with a state_as handed over it locates the Authentication Session") {
      test("a known state yields the mapped session") {
        ZetaCookieProvider.attachStateAsToSession(session, STATE_AS)

        provider.get(CookieType.AUTH_SESSION_ID) shouldBe MAPPED_AUTH_SESSION_ID
        verify(exactly = 0) { delegate.get(CookieType.AUTH_SESSION_ID) }
      }

      test("an unknown state yields no session even though a cookie is present") {
        ZetaCookieProvider.attachStateAsToSession(session, "unknown-state")

        provider.get(CookieType.AUTH_SESSION_ID).shouldBeNull()
      }

      test("other cookies still come from the default provider") {
        ZetaCookieProvider.attachStateAsToSession(session, STATE_AS)
        every { delegate.get(CookieType.AUTH_RESTART) } returns "restart-cookie"

        provider.get(CookieType.AUTH_RESTART) shouldBe "restart-cookie"
      }
    }
  }
}
