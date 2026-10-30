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

import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator.buildCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.intermediateCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstAdmission
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfession
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfessionInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName

class CertificateGeneratorTest : ZetaGuardFunSpec() {
  val objectUnderTest = CertificateChain()

  init {
    test("Certificate chain should link issuers and subjects correctly") {
      with(objectUnderTest) {
        leafCert.issuerX500Principal shouldBe intermediateCert.subjectX500Principal
        intermediateCert.issuerX500Principal shouldBe rootCert.subjectX500Principal
        rootCert.issuerX500Principal shouldBe rootCert.subjectX500Principal
      }
    }

    test("Signatures should be valid up the chain") {
      with(objectUnderTest) {
        validateCertificateSignature(leafCert, intermediateCert.publicKey).isRight() shouldBe true
        validateCertificateSignature(intermediateCert, rootCert.publicKey).isRight() shouldBe true
        validateCertificateSignature(rootCert, rootCert.publicKey).isRight() shouldBe true
      }
    }

    test("Verify certificates") {
      with(objectUnderTest) {
        rootCert.isRoot() shouldBe true
        intermediateCert.isRoot() shouldBe false
        leafCert.isRoot() shouldBe false

        intermediateCert.publicKey shouldBe intermediateKeyPair.public
        leafCert.publicKey shouldBe leafKeyPair.public
        rootCert.publicKey shouldBe rootKeyPair.public

        rootCert.basicConstraints shouldBeGreaterThan 1000
        intermediateCert.basicConstraints shouldBeGreaterThan 1000
        leafCert.basicConstraints shouldBe -1
      }
    }

    test("Certificate chain should pass PKIX validation") {
      with(objectUnderTest) {
        val validatorResult = validateCertificateChain(rootCert, listOf(leafCert, intermediateCert)).shouldBeRight()

        validatorResult.publicKey shouldBe leafCert.publicKey
      }
    }

    test("Just checking intermediate certificate") { //
      with(objectUnderTest) { validateCertificateChain(intermediateCert, listOf(leafCert)).shouldBeRight() }
    }

    test("Checking gematik certificates") {
      leafCertificate.subjectCommonName() shouldBe CRT_GEMATIK_LEAF_NAME
      leafCertificate.subjectOrganisationName() shouldBe CRT_GEMATIK_LEAF_ORGANISATION

      val professionInfo = leafCertificate.extractExtension<AdmissionSyntax>(admission)?.firstAdmission()?.firstProfessionInfo()!!
      val professionIdentifier = professionInfo.firstProfession()!!
      val professionOID = professionIdentifier.id
      val telematikID = professionInfo.registrationNumber

      professionOID shouldBe betriebsstaetteArzt.id
      telematikID shouldBe TELEMATIK_ID

      validateCertificateChain(intermediateCertificate, listOf(leafCertificate)).shouldBeRight()
    }

    test("Validating certificate fails") {
      with(objectUnderTest) {
        val keyPair = generateKeyPair()
        val unrelatedCertificate =
            buildCertificate(
                subjectName = CRT_GEMATIK_ROOT_DN,
                subjectKeyPair = keyPair,
                issuerName = CRT_GEMATIK_ROOT_DN,
                issuerKeyPair = keyPair,
                isCA = true,
                isRootCA = true,
                createAdmissionExtension = false,
            )

        validateCertificateChain(unrelatedCertificate, listOf(leafCert, intermediateCert)).shouldBeLeft() shouldContain "validation failed"
      }
    }

    test("Key Usage should be correct") {
      with(objectUnderTest) {
        leafCert.keyUsage[0] shouldBe true // digitalSignature
        leafCert.keyUsage[5] shouldBe false // keyCertSign

        intermediateCert.keyUsage[5] shouldBe true // keyCertSign

        rootCert.keyUsage.size shouldBeGreaterThan 6
        rootCert.keyUsage[5] shouldBe true // keyCertSign
      }
    }
    test("Read extensions from certificate") {
      with(objectUnderTest) {
        leafCert.nonCriticalExtensionOIDs shouldContain admission.id

        val admissionSyntax = leafCert.extractExtension<AdmissionSyntax>(admission)
        admissionSyntax?.contentsOfAdmissions?.shouldHaveSize(1)
        admissionSyntax?.admissionAuthority?.shouldBe(GeneralName(X500Name(DN_GEMATIK)))
        val admissions = admissionSyntax?.contentsOfAdmissions[0]
        admissions?.professionInfos?.shouldHaveSize(1)
        val professionInfo = admissions?.professionInfos[0]
        professionInfo?.registrationNumber shouldBe TELEMATIK_ID
        professionInfo?.professionOIDs.shouldContainExactly(betriebsstaetteArzt)
      }
    }
  }
}

class CertificateChain(
    curve: String = CURVE_BRAINPOOL,
    rootDN: String = CRT_GEMATIK_ROOT_DN,
    intermediateDN: String = CRT_GEMATIK_INTERMEDIATE_DN,
    leafDN: String = CRT_GEMATIK_LEAF_DN,
) {
  val rootKeyPair = generateKeyPair(curve)
  val rootCert =
      buildCertificate(
          subjectName = rootDN,
          subjectKeyPair = rootKeyPair,
          issuerName = rootDN,
          issuerKeyPair = rootKeyPair,
          isCA = true,
          isRootCA = true,
          createAdmissionExtension = false,
      )

  val intermediateKeyPair = generateKeyPair(curve)
  val intermediateCert =
      buildCertificate(
          subjectName = intermediateDN,
          subjectKeyPair = intermediateKeyPair,
          issuerName = rootCert.subjectX500Principal.name,
          issuerKeyPair = rootKeyPair,
          isCA = true,
      )

  val leafKeyPair = generateKeyPair(curve)
  val leafCert =
      buildCertificate(
          subjectName = leafDN,
          subjectKeyPair = leafKeyPair,
          issuerName = intermediateCert.subjectX500Principal.name,
          issuerKeyPair = intermediateKeyPair,
          isCA = false,
      )
}
