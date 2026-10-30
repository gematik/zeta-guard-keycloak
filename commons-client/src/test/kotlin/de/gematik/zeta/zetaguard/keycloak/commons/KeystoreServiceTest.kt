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

import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.publicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.isIntermediate
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import java.io.IOException
import java.security.SignatureException

class KeystoreServiceTest : ZetaGuardFunSpec() {
  init {
    val objectUnderTest = SMCBTokenHelper.keystoreService

    test("Wrong password") {
      val stream = KeystoreServiceTest::class.java.getResourceAsStream("/smcb-certificates.p12")!!
      val message = shouldThrow<IOException> { KeystoreService(stream, "wrong").aliases() }.message!!

      message shouldContain "password"
    }

    test("Read certificates") {
      val aliases = objectUnderTest.aliases()

      aliases shouldContainAll listOf(CRT_GEMATIK_LEAF.uppercase(), CRT_GEMATIK_INTERMEDIATE.uppercase())

      objectUnderTest.hasCertificate("jens.smcb-ca21_test-only") shouldBe false
      objectUnderTest.hasCertificate(CRT_GEMATIK_ROOT) shouldBe true

      objectUnderTest.hasCertificate(intermediateCertificate) shouldBe true

      val gematik = objectUnderTest.findCertificate(CRT_GEMATIK_ROOT).shouldNotBeNull()
      gematik.isRoot() shouldBe true
      gematik.isIntermediate() shouldBe false
      gematik.publicKey.algorithm shouldBe "EC"

      intermediateCertificate.isRoot() shouldBe false
      intermediateCertificate.isIntermediate() shouldBe true
      leafCertificate.issuerX500Principal shouldBe intermediateCertificate.subjectX500Principal
      objectUnderTest.findIssuerCertificate(leafCertificate) shouldBe intermediateCertificate
    }

    test("Check public key validation") {
      intermediateCertificate.javaClass.name shouldStartWith "org.bouncycastle"

      val exception = shouldThrow<SignatureException> { intermediateCertificate.verify(intermediateCertificate.publicKey) }.message

      exception shouldNotContain "Curve not supported"
      exception shouldBe "certificate does not verify with supplied key"
    }

    test("Leaf certificate private key") { publicKey shouldBe leafCertificate.publicKey }
  }
}
