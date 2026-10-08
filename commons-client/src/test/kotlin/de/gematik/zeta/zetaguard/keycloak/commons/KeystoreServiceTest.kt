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

import de.gematik.zeta.zetaguard.keycloak.commons.ClientCertificateService.getCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.ClientCertificateService.getPrivateKey
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstAdmission
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfession
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfessionInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.isIntermediate
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldContainAll
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain
import io.kotest.matchers.string.shouldStartWith
import java.io.IOException
import java.security.SignatureException
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax

class KeystoreServiceTest : ZetaGuardFunSpec() {
  init {
    val stream = SMCBTokenHelper::class.java.getResourceAsStream("/smcb-certificates.p12")!!
    val objectUnderTest = KeystoreService(stream, SMCB_KEYSTORE_PASSWORD)
    val intermediateCertificate = objectUnderTest.findCertificate(CRT_GEMATIK_INTERMEDIATE)!!
    val smcb = SMCBTokenHelper()

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
      smcb.leafCertificate.issuerX500Principal shouldBe intermediateCertificate.subjectX500Principal
      objectUnderTest.findIssuerCertificate(smcb.leafCertificate) shouldBe intermediateCertificate
    }

    test("Checking gematik certificates") {
      smcb.leafCertificate.subjectCommonName() shouldStartWith CRT_GEMATIK_LEAF_NAME
      smcb.leafCertificate.subjectOrganisationName() shouldBe CRT_GEMATIK_LEAF_ORGANISATION

      val professionInfo = smcb.leafCertificate.extractExtension<AdmissionSyntax>(admission)?.firstAdmission()?.firstProfessionInfo()!!
      val professionIdentifier = professionInfo.firstProfession()!!
      val professionOID = professionIdentifier.id
      val telematikID = professionInfo.registrationNumber

      professionOID shouldBe betriebsstaetteArzt.id
      telematikID shouldStartWith TELEMATIK_ID

      validateCertificateChain(intermediateCertificate, listOf(smcb.leafCertificate)).shouldBeRight()
    }

    test("Checking zipped certificates") {
      getPrivateKey(10).shouldNotBeNull()
      getPrivateKey(100).shouldNotBeNull()

      validateCertificateChain(intermediateCertificate, listOf(getCertificate(10))).shouldBeRight()
      validateCertificateChain(intermediateCertificate, listOf(getCertificate(100))).shouldBeRight()
    }

    test("Check public key validation") {
      intermediateCertificate.javaClass.name shouldStartWith "org.bouncycastle"

      val exception = shouldThrow<SignatureException> { intermediateCertificate.verify(intermediateCertificate.publicKey) }.message

      exception shouldNotContain "Curve not supported"
      exception shouldBe "certificate does not verify with supplied key"
    }

    test("Leaf certificate private key") { smcb.publicKey shouldBe smcb.leafCertificate.publicKey }
  }
}
