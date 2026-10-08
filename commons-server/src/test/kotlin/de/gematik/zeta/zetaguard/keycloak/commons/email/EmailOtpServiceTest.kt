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

class EmailOtpServiceTest : FunSpec() {
  init {
    test("maskEmail keeps first local and host characters") {
      maskEmail("alice@domain.de") shouldBe "a*@d*.de"
    }

    test("maskEmail falls back for malformed input") {
      maskEmail("not-an-email") shouldBe "*"
    }

    test("issue stores a numeric OTP and verify consumes it once") {
      val store = linkedMapOf<String, MutableMap<String, String>>()
      val singleUse = mockk<SingleUseObjectProvider>()
      every { singleUse.put(any(), any(), any()) } answers
          {
            store[firstArg()] = (thirdArg() as Map<String, String>).toMutableMap()
          }
      every { singleUse[any()] } answers { store[firstArg()] }
      every { singleUse.remove(any()) } answers { store.remove(firstArg()) }

      val session = mockk<KeycloakSession>()
      every { session.singleUseObjects() } returns singleUse

      val otp = EmailOtpService.issue(session, "mobile-client")
      otp.shouldHaveLength(6)
      otp shouldMatch Regex("\\d{6}")
      verify { singleUse.put("zeta-email-otp:mobile-client", 300L, mapOf("otp" to otp)) }

      EmailOtpService.verify(session, "mobile-client", otp) shouldBe true
      EmailOtpService.verify(session, "mobile-client", otp) shouldBe false
    }

    test("verify rejects blank and wrong codes") {
      val singleUse = mockk<SingleUseObjectProvider>()
      every { singleUse[any()] } returns mapOf("otp" to "123456")
      val session = mockk<KeycloakSession>()
      every { session.singleUseObjects() } returns singleUse

      EmailOtpService.verify(session, "mobile-client", null) shouldBe false
      EmailOtpService.verify(session, "mobile-client", " ") shouldBe false
      EmailOtpService.verify(session, "mobile-client", "000000") shouldBe false
    }
  }
}
