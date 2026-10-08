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

import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreMetaService
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import java.time.Instant
import java.util.Date

class KeystoreMetaServiceTest : ZetaGuardFunSpec() {
  init {
    val storeStream = SMCBTokenHelper::class.java.getResourceAsStream("/smcb-certificates.p12")!!
    val metaStream = SMCBTokenHelper::class.java.getResourceAsStream("/smcb-certificates-meta.json")!!
    val objectUnderTest = KeystoreMetaService(storeStream, SMCB_KEYSTORE_PASSWORD, metaStream)

    test("Read certificate meta") {
      // leaf certificates should not have metadata
      val leafCertificate = objectUnderTest.findCertificate(CRT_GEMATIK_LEAF).shouldNotBeNull()
      objectUnderTest.getTsp(leafCertificate) shouldBe null
      objectUnderTest.getRevokedSince(leafCertificate) shouldBe null

      val gematik = objectUnderTest.findCertificate(CRT_GEMATIK_ROOT).shouldNotBeNull()
      objectUnderTest.getTsp(gematik) shouldBe "root"
      objectUnderTest.getRevokedSince(gematik) shouldBe null

      val intermediateCertificate = objectUnderTest.findCertificate(CRT_GEMATIK_INTERMEDIATE).shouldNotBeNull()
      objectUnderTest.getTsp(intermediateCertificate) shouldBe "gematik"
      objectUnderTest.getRevokedSince(intermediateCertificate) shouldBe Date.from(Instant.parse("2020-08-05T14:00:00Z"))
    }

    test("Aliases without a meta entry are reported") {
      // A leaf certificate legitimately has no meta entry, so this is a diagnostic, not a reason to reject the store.
      objectUnderTest.aliasesWithoutMeta() shouldContainExactly setOf(CRT_GEMATIK_LEAF.uppercase())
    }
  }
}
