/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.pkcs12

import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_INTERMEDIATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_ROOT
import de.gematik.zeta.zetaguard.keycloak.commons.server.getPublicKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.isIntermediate
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import java.io.IOException
import java.security.SignatureException

const val KEYSTORE_PASSWORD = "tyqvHpFoHdu68yRE+0F4q/I"

class KeystoreServiceTest : FunSpec() {
  init {
    val certificate = objectUnderTest.getCertificate(CRT_GEMATIK_INTERMEDIATE)
    val leaf = objectUnderTest.getCertificate(CRT_GEMATIK_LEAF)

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

      val gematik = objectUnderTest.getCertificate(CRT_GEMATIK_ROOT)
      gematik.isRoot() shouldBe true
      gematik.isIntermediate() shouldBe false
      gematik.publicKey.algorithm shouldBe "EC"

      certificate.isRoot() shouldBe false
      certificate.isIntermediate() shouldBe true
      leaf.issuerX500Principal shouldBe certificate.subjectX500Principal
      objectUnderTest.findIssuerCertificate(leaf) shouldBe certificate
    }

    test("Brain pool curves are accepted by BouncyCastle") {
      certificate.javaClass.name shouldStartWith "org.bouncycastle"

      val exception = shouldThrow<SignatureException> { certificate.verify(certificate.publicKey) }.message

      exception shouldNotContain "Curve not supported"
      exception shouldBe "certificate does not verify with supplied key"
    }

    test("Leaf certificate private key") {
      val privateKey = objectUnderTest.getPrivateKey(CRT_GEMATIK_LEAF)
      val publicKey = privateKey.getPublicKey()

      publicKey shouldBe leaf.publicKey
    }
  }

  companion object {
    init {
      setupBouncyCastle()
    }

    private val stream = KeystoreServiceTest::class.java.getResourceAsStream("/smcb-certificates.p12")!!
    val objectUnderTest = KeystoreService(stream, KEYSTORE_PASSWORD)

    fun KeystoreService.getPrivateKey(name: String) = getPrivateKey(name, KEYSTORE_PASSWORD)
  }
}
