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
package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator.buildCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.PKIUtil.generateECKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_INTERMEDIATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF_DN
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF_ORGANISATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_ROOT_DN
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.betriebsstaetteArzt
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstAdmission
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfession
import de.gematik.zeta.zetaguard.keycloak.commons.server.firstProfessionInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.isRoot
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectCommonName
import de.gematik.zeta.zetaguard.keycloak.commons.server.subjectOrganisationName
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateChain
import de.gematik.zeta.zetaguard.keycloak.commons.server.validateCertificateSignature
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreServiceTest
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.KeyPair
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.GeneralName

class CertificateGeneratorTest : FunSpec() {
  init {
    test("Certificate chain should link issuers and subjects correctly") {
      leafCert.issuerX500Principal shouldBe intermediateCert.subjectX500Principal
      intermediateCert.issuerX500Principal shouldBe rootCert.subjectX500Principal
      rootCert.issuerX500Principal shouldBe rootCert.subjectX500Principal
    }

    test("Signatures should be valid up the chain") {
      validateCertificateSignature(leafCert, intermediateCert.publicKey).isRight() shouldBe true
      validateCertificateSignature(intermediateCert, rootCert.publicKey).isRight() shouldBe true
      validateCertificateSignature(rootCert, rootCert.publicKey).isRight() shouldBe true
    }

    test("Verify certificates") {
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

    test("Certificate chain should pass PKIX validation") {
      val validatorResult = validateCertificateChain(rootCert, leafCert, intermediateCert).shouldBeRight()

      validatorResult.publicKey shouldBe leafCert.publicKey
    }

    test("Just checking intermediate certificate") { //
      validateCertificateChain(intermediateCert, leafCert).shouldBeRight()
    }

    test("Checking gematik certificates") {
      val keystoreService = KeystoreServiceTest.objectUnderTest
      val certificate = keystoreService.getCertificate(CRT_GEMATIK_INTERMEDIATE)
      val leaf = keystoreService.getCertificate(CRT_GEMATIK_LEAF)

      leaf.subjectCommonName() shouldBe CRT_GEMATIK_LEAF_NAME
      leaf.subjectOrganisationName() shouldBe CRT_GEMATIK_LEAF_ORGANISATION

      val professionInfo = leaf.extractExtension<AdmissionSyntax>(admission)?.firstAdmission()?.firstProfessionInfo()!!
      val professionIdentifier = professionInfo.firstProfession()!!
      val professionOID = professionIdentifier.id
      val telematikID = professionInfo.registrationNumber

      professionOID shouldBe betriebsstaetteArzt.id
      telematikID shouldBe TELEMATIK_ID

      validateCertificateChain(certificate, leaf).shouldBeRight()
    }

    test("Validating certificate fails") {
      val unrelatedCertificate = buildRootCertificate(generateECKeyPair())

      validateCertificateChain(unrelatedCertificate, leafCert, intermediateCert).shouldBeLeft() shouldContain "validation failed"
    }

    test("Key Usage should be correct") {
      leafCert.keyUsage[0] shouldBe true // digitalSignature
      leafCert.keyUsage[5] shouldBe false // keyCertSign

      intermediateCert.keyUsage[5] shouldBe true // keyCertSign

      rootCert.keyUsage.size shouldBeGreaterThan 6
      rootCert.keyUsage[5] shouldBe true // keyCertSign
    }

    test("Read extensions from certificate") {
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

  companion object {
    val rootKeyPair = generateECKeyPair(CURVE_BRAINPOOL)
    val rootCert = buildRootCertificate(rootKeyPair)

    val intermediateKeyPair = generateECKeyPair(CURVE_BRAINPOOL)
    val intermediateCert =
        buildCertificate(
            subjectName =
                "C=DE, O=gematik GmbH NOT-VALID, OU=Institution des Gesundheitswesens-CA der Telematikinfrastruktur, CN=GEM.SMCB-CA8 TEST-ONLY",
            subjectKeyPair = intermediateKeyPair,
            issuerName = rootCert.subjectX500Principal.name,
            issuerKeyPair = rootKeyPair,
            isCA = true,
        )

    val leafKeyPair = generateECKeyPair(CURVE_BRAINPOOL)
    val leafCert =
        buildCertificate(
            subjectName = CRT_GEMATIK_LEAF_DN,
            subjectKeyPair = leafKeyPair,
            issuerName = intermediateCert.subjectX500Principal.name,
            issuerKeyPair = intermediateKeyPair,
            isCA = false,
        )

    private fun buildRootCertificate(keyPair: KeyPair): X509Certificate =
        buildCertificate(
            subjectName = CRT_GEMATIK_ROOT_DN,
            subjectKeyPair = keyPair,
            issuerName = CRT_GEMATIK_ROOT_DN,
            issuerKeyPair = keyPair,
            isCA = true,
            isRootCA = true,
        )
  }
}
