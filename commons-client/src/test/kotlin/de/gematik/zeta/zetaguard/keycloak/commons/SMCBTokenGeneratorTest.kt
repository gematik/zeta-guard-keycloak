/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.BETRIEBSSTAETTE_ARZT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CRT_GEMATIK_LEAF
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.betriebsstaetteArzt
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPEM
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreServiceTest
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreServiceTest.Companion.getPrivateKey
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainOnly
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import java.security.KeyPair
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1OctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.ASN1Sequence
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.isismtt.x509.Admissions
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
import org.bouncycastle.asn1.x500.DirectoryString
import org.bouncycastle.jce.PrincipalUtil
import org.bouncycastle.jce.X509Principal
import org.keycloak.OAuth2Constants
import org.keycloak.jose.jws.JWSHeader
import org.keycloak.representations.IDToken

class SMCBTokenGeneratorTest : FunSpec() {
  init {
    val objectUnderTest = SMCBTokenGenerator()
    val token = objectUnderTest.generateSMCBToken()
    val (jwt, header) = token.toIDTokenInfo(objectUnderTest.subjectKeyPair.createVerifierContext())

    test("Validate JWT") {
      val pem = objectUnderTest.certificate.toPEM()
      pem shouldContain "\nMII"

      checkJWT(header, jwt)
    }

    test("Validate certificate") {
      val certificate = header.x5c[0].toCertificate()
      val subjectName = PrincipalUtil.getSubjectX509Principal(certificate)
      val issuerName = PrincipalUtil.getIssuerX509Principal(certificate)

      certificate shouldBe objectUnderTest.certificate

      subjectName shouldBe PrincipalUtil.getSubjectX509Principal(objectUnderTest.certificate)
      issuerName shouldBe PrincipalUtil.getIssuerX509Principal(objectUnderTest.certificate)
      subjectName shouldBe X509Principal(DN_PRAXIS)
      issuerName shouldBe X509Principal(DN_GEMATIK)
    }

    test("Validate certificate admissions") {
      val certificate = objectUnderTest.certificate
      checkCertificateExtensions(certificate, VALID_TELEMATIK_ID)
    }

    test("Validate gematik certificate") {
      val keystoreService = KeystoreServiceTest.objectUnderTest
      val privateKey = keystoreService.getPrivateKey(CRT_GEMATIK_LEAF)
      val leafCertificate = keystoreService.getCertificate(CRT_GEMATIK_LEAF)
      val publicKey = leafCertificate.publicKey
      val subjectKeyPair = KeyPair(publicKey, privateKey)
      val smcbTokenGenerator = SMCBTokenGenerator(subjectKeyPair = subjectKeyPair)
      val token = smcbTokenGenerator.generateSMCBToken(certificateChain = listOf(leafCertificate))
      val (jwt, header) = token.toIDTokenInfo(subjectKeyPair.createVerifierContext())

      checkJWT(header, jwt)
      checkCertificateExtensions(leafCertificate, VALID_TELEMATIK_ID)
    }
  }

  @Suppress("SameParameterValue")
  private fun checkCertificateExtensions(certificate: X509Certificate, telematikId: String) {
    val extBytes = certificate.getExtensionValue(admission.id)
    val octetString = ASN1Primitive.fromByteArray(extBytes) as ASN1OctetString
    val sequence = ASN1Sequence.getInstance(octetString.octets)
    val admissionSyntax = AdmissionSyntax.getInstance(sequence)

    admissionSyntax.contentsOfAdmissions.size shouldBe 1
    val admissions = admissionSyntax.contentsOfAdmissions.first() as Admissions

    admissions.professionInfos.size shouldBe 1
    val professionInfo = admissions.professionInfos.first() as ProfessionInfo

    professionInfo.professionOIDs.shouldContainOnly(betriebsstaetteArzt)
    professionInfo.registrationNumber shouldBe telematikId

    professionInfo.professionItems.size shouldBe 1
    val professionItem = professionInfo.professionItems.first() as DirectoryString
    professionItem.string shouldBe BETRIEBSSTAETTE_ARZT
  }

  private fun checkJWT(header: JWSHeader, jwt: IDToken) {
    header.algorithm.name shouldBe "ES256"
    header.type shouldBe OAuth2Constants.JWT
    header.x5c.size shouldBe 1

    // Check values of https://github.com/gematik/zeta/blob/main/src/schemas/smb-id-token-jwt.yaml
    jwt.id.shouldNotBeNull()
    jwt.nonce.shouldNotBeNull() // To be checked in integration test
    jwt.issuer shouldBe ZETA_CLIENT
    jwt.subject shouldBe VALID_TELEMATIK_ID
    jwt.audience shouldContain ZETA_CLIENT
    (jwt.iat * 1000) shouldBeLessThanOrEqual System.currentTimeMillis()
    (jwt.exp * 1000) shouldBeGreaterThan System.currentTimeMillis()
  }

  companion object {
    init {
      setupBouncyCastle()
    }
  }
}
