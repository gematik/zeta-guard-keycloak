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
package de.gematik.zeta.zetaguard.keycloak.commons.email

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveLength
import io.kotest.matchers.string.shouldMatch
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import org.keycloak.models.KeycloakSession
import org.keycloak.models.SingleUseObjectProvider

class EmailOTPServiceTest : FunSpec() {
  init {
    test("issue stores a numeric OTP and verify consumes it once") {
      val (session, singleUse) = sessionWithStore()

      val otp = EmailOTPService.issue(session, "mobile-client", "alice@example.de")
      otp.shouldHaveLength(6)
      otp shouldMatch Regex("\\d{6}")
      // the address itself is not stored
      verify { singleUse.put("zeta-email-otp:mobile-client", 300L, match { it["otp"] == otp && it["email"] != "alice@example.de" }) }

      EmailOTPService.verify(session, "mobile-client", otp, "alice@example.de") shouldBe true
      EmailOTPService.verify(session, "mobile-client", otp, "alice@example.de") shouldBe false
    }

    test("verify accepts the code only for the address it was issued for") {
      val (session) = sessionWithStore()
      val otp = EmailOTPService.issue(session, "mobile-client", "alice@example.de")

      EmailOTPService.verify(session, "mobile-client", otp, "mallory@example.de") shouldBe false
      EmailOTPService.verify(session, "mobile-client", otp, null) shouldBe false
      // the challenge stays open, spelling of the address does not matter
      EmailOTPService.verify(session, "mobile-client", otp, " Alice@Example.de ") shouldBe true
    }

    test("verify rejects blank and wrong codes") {
      val (session) = sessionWithStore()
      EmailOTPService.issue(session, "mobile-client", "alice@example.de")

      EmailOTPService.verify(session, "mobile-client", null, "alice@example.de") shouldBe false
      EmailOTPService.verify(session, "mobile-client", " ", "alice@example.de") shouldBe false
      EmailOTPService.verify(session, "mobile-client", "abcdef", "alice@example.de") shouldBe false
    }
  }

  private fun sessionWithStore(): Pair<KeycloakSession, SingleUseObjectProvider> {
    val store = linkedMapOf<String, Map<String, String>>()
    val singleUse = mockk<SingleUseObjectProvider>()
    every { singleUse.put(any(), any(), any()) } answers { store[firstArg()] = thirdArg() }
    every { singleUse[any()] } answers { store[firstArg()] }
    every { singleUse.remove(any()) } answers { store.remove(firstArg()) }
    val session = mockk<KeycloakSession>()
    every { session.singleUseObjects() } returns singleUse

    return session to singleUse
  }
}
