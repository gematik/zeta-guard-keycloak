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
package de.gematik.zeta.zetaguard.keycloak.plugins

import de.gematik.zeta.zetaguard.keycloak.client_assertion.AttestationUtilTest
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.GoogleCertificateStatusService
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.AndroidRevocationReason
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.AndroidRevocationStatus
import de.gematik.zeta.zetaguard.keycloak.plugins.attestation.google.GoogleRevocationStatusList
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.maps.shouldHaveSize
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class GoogleRevocationStatusListTest : ZetaGuardFunSpec() {
  init {
    test("Parse example revocation status list") {
      val stream = GoogleRevocationStatusListTest::class.java.getResourceAsStream("/status.json")!!
      val statusList = stream.toObject<GoogleRevocationStatusList>()

      statusList.entries shouldHaveSize 3

      val revoked = statusList.entries["2c8cdddfd5e03bfc"].shouldNotBeNull()
      revoked.status shouldBe AndroidRevocationStatus.REVOKED
      revoked.expires shouldBe "2020-11-13"
      revoked.reason shouldBe AndroidRevocationReason.KEY_COMPROMISE
      revoked.comment shouldBe "Key stored on unsecure system"

      val suspended = statusList.entries["c8966fcb2fbb0d7a"].shouldNotBeNull()
      suspended.status shouldBe AndroidRevocationStatus.SUSPENDED
      suspended.expires.shouldBeNull()
      suspended.reason shouldBe AndroidRevocationReason.SOFTWARE_FLAW

      statusList.entries["cafebabe"].shouldBeNull()
    }

    test("Test service") {
      val stream = GoogleRevocationStatusListTest::class.java.getResourceAsStream("/status.json")!!
      val objectUnderTest = GoogleCertificateStatusService(stream)

      objectUnderTest.isValid("cafebabe".toBigInteger(16)).shouldBeTrue()
      objectUnderTest.isValid(AttestationUtilTest.APPLE_ROOT_CA).shouldBeTrue()
      objectUnderTest.isValid("2c8cdddfd5e03bfc".toBigInteger(16)).shouldBeFalse()
      objectUnderTest.isValid("c8966fcb2fbb0d7a".toBigInteger(16)).shouldBeFalse()
      objectUnderTest.isValid("12365028775357944392".toBigInteger(16)).shouldBeFalse()
      objectUnderTest.isValid("12365028775357944392".toBigInteger(10)).shouldBeFalse()

      objectUnderTest.revokedCertificates().contains("2c8cdddfd5e03bfc").shouldBeTrue()
      AttestationUtilTest.APPLE_ROOT_CA.serialNumber shouldBe "0bf3be0ef1cdd2e0fb8c6e721f621798".toBigInteger(16)
    }
  }
}
