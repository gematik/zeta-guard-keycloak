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
@file:Suppress("DEPRECATION")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator.buildCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.leafCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.SMCBTokenHelper.subjectKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.createVerifierContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPEM
import io.kotest.matchers.collections.shouldContain
import io.kotest.matchers.collections.shouldContainOnly
import io.kotest.matchers.longs.shouldBeGreaterThan
import io.kotest.matchers.longs.shouldBeLessThanOrEqual
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
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

class SMCBTokenGeneratorTest : ZetaGuardFunSpec() {
  init {
    val objectUnderTest = SMCBTokenGenerator(generateKeyPair())
    val certificate =
        buildCertificate(
            subjectName = DN_PRAXIS,
            subjectKeyPair = generateKeyPair(),
            issuerName = DN_GEMATIK,
            issuerKeyPair = generateKeyPair(),
            isCA = false,
        )
    val token = objectUnderTest.generateSMCBToken(nonceString = "noncence", certificateChain = listOf(certificate))
    val (jwt, header) = token.toIDTokenInfo(objectUnderTest.keys.keypair.public.createVerifierContext())

    test("Validate JWT") {
      val pem = certificate.toPEM()
      pem shouldContain "-----BEGIN CERTIFICATE-----\nMII"

      checkJWT(header, jwt)
    }

    test("Write publicy key pem") {
      val pem = objectUnderTest.keys.publicKeyPEM
      pem shouldContain "-----BEGIN PUBLIC KEY-----\nMFk"

      checkJWT(header, jwt)
    }

    test("Validate certificate") {
      val certificate = header.x5c[0].toCertificate()
      val subjectName = PrincipalUtil.getSubjectX509Principal(certificate)
      val issuerName = PrincipalUtil.getIssuerX509Principal(certificate)

      certificate shouldBe certificate

      subjectName shouldBe PrincipalUtil.getSubjectX509Principal(certificate)
      issuerName shouldBe PrincipalUtil.getIssuerX509Principal(certificate)
      subjectName shouldBe X509Principal(DN_PRAXIS)
      issuerName shouldBe X509Principal(DN_GEMATIK)
    }

    test("Validate certificate admissions") { checkCertificateExtensions(certificate, TELEMATIK_ID) }

    test("Validate gematik certificate") {
      val tokenGenerator = SMCBTokenGenerator(subjectKeyPair = subjectKeyPair)
      val token = tokenGenerator.generateSMCBToken(nonceString = "noncence", certificateChain = listOf(leafCertificate))
      val (jwt, header) = token.toIDTokenInfo(subjectKeyPair.public.createVerifierContext())

      checkJWT(header, jwt)
      checkCertificateExtensions(leafCertificate, TELEMATIK_ID)
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
    jwt.subject shouldBe TELEMATIK_ID
    jwt.audience shouldContain ZETA_CLIENT
    (jwt.iat * 1000) shouldBeLessThanOrEqual System.currentTimeMillis()
    (jwt.exp * 1000) shouldBeGreaterThan System.currentTimeMillis()
  }
}
