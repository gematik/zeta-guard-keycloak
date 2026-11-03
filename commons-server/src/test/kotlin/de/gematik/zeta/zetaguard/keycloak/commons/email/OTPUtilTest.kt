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

import de.gematik.zeta.zetaguard.keycloak.commons.OTPUtil.createOTP
import de.gematik.zeta.zetaguard.keycloak.commons.maskEmail
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldHaveLength

class OTPUtilTest : FunSpec() {
  init {
    test("maskEmail keeps first local and host characters") {
      "alice@domain.de".maskEmail() shouldBe "a*@d*.de"
      "alice@bla.foo.bar".maskEmail() shouldBe "a*@b*.f*.bar"
      "FirstName.LastName@EasierReading.org".maskEmail() shouldBe "F*.L*@E*.org"
      "\"very.(),:;<>[]\".VERY.\"very@\\ \"very\".unusual\"@strange.example.com".maskEmail() shouldBe "\"*.(*.V*.\"*.u*@s*.e*.com"
      "postmaster@[IPv6:2001:0db8:85a3:0000:0000:8a2e:0370:7334]".maskEmail() shouldBe "p*@[*"
      "I❤\uFE0FCHOCOLATE@example.com".maskEmail() shouldBe "I*@e*.com"
    }

    test("maskEmail falls back for malformed input") {
      "not-an-email".maskEmail() shouldBe "*"
    }

    test("Create OTP") {
      createOTP() shouldHaveLength 6
    }
  }
}
