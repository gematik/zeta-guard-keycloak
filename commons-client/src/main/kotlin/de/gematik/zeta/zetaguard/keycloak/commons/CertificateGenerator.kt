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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.BETRIEBSSTAETTE_ARZT
import de.gematik.zeta.zetaguard.keycloak.commons.server.admission
import de.gematik.zeta.zetaguard.keycloak.commons.server.betriebsstaetteArzt
import de.gematik.zeta.zetaguard.keycloak.commons.server.gematikPolicy
import de.gematik.zeta.zetaguard.keycloak.commons.server.smcbAuth
import java.math.BigInteger
import java.security.KeyPair
import java.security.PublicKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date
import java.util.concurrent.TimeUnit
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.isismtt.x509.Admissions
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
import org.bouncycastle.asn1.x500.DirectoryString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.CertificatePolicies
import org.bouncycastle.asn1.x509.ExtendedKeyUsage
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.asn1.x509.GeneralNames
import org.bouncycastle.asn1.x509.KeyPurposeId
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.asn1.x509.PolicyInformation
import org.bouncycastle.asn1.x509.PolicyQualifierInfo
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

object CertificateGenerator {
  /**
   * Build a single X.509 Certificate optionally signed by another X.509 Certificate. Format and fields are created according to
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_PKI/latest/#4.7.2.1
   */
  fun buildCertificate(
      subjectName: String,
      subjectKeyPair: KeyPair,
      issuerName: String,
      issuerKeyPair: KeyPair,
      isCA: Boolean,
      isRootCA: Boolean = false,
      sans: List<GeneralName>? = null,
  ): X509Certificate {
    val certBuilder = createCertificateBuilder(subjectName, issuerName, subjectKeyPair.public)
    val extUtils = JcaX509ExtensionUtils()

    // Subject Key Identifier (SKI) - Identifies this cert's public key
    val ski = extUtils.createSubjectKeyIdentifier(subjectKeyPair.public)
    certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski)

    // Authority Key Identifier (AKI) - Identifies the signing cert's public key
    // For self-signed, it's the same as SKI.
    val signingKeyForAki = if (isRootCA) subjectKeyPair.public else issuerKeyPair.public
    val aki = extUtils.createAuthorityKeyIdentifier(signingKeyForAki)
    certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki)

    // Basic Constraints - Identifies if this is a CA
    certBuilder.addExtension(Extension.basicConstraints, true, BasicConstraints(isCA))

    if (isCA) { // Key Usage for a CA: Signing other certs and CRLs
      val keyUsage = KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign)
      certBuilder.addExtension(Extension.keyUsage, true, keyUsage)
    } else { // Key Usage for a Leaf (End-Entity): Digital Signature, Key Encipherment
      val keyUsage = KeyUsage(KeyUsage.digitalSignature or KeyUsage.keyEncipherment)
      certBuilder.addExtension(Extension.keyUsage, true, keyUsage)

      // Extended Key Usage (EKU) - What this cert is for
      val eku = ExtendedKeyUsage(arrayOf(KeyPurposeId.id_kp_clientAuth))
      certBuilder.addExtension(Extension.extendedKeyUsage, false, eku)

      // Admissions containing Profession OIDs
      val admissionSyntax = buildAdmissionSyntax()
      certBuilder.addExtension(admission, false, admissionSyntax)

      // Certificate policies reference
      val certificatePolicies = buildCertificatePolicies()
      certBuilder.addExtension(Extension.certificatePolicies, false, certificatePolicies)

      // Subject Alternative Names (SANs)
      if (!sans.isNullOrEmpty()) {
        certBuilder.addExtension(Extension.subjectAlternativeName, false, GeneralNames(sans.toTypedArray()))
      }
    }

    val signer = JcaContentSignerBuilder(issuerKeyPair.signingAlgorithm()).build(issuerKeyPair.private)

    return JcaX509CertificateConverter().getCertificate(certBuilder.build(signer))
  }

  private fun createCertificateBuilder(subjectName: String, issuerName: String, subjectKey: PublicKey): JcaX509v3CertificateBuilder {
    val now = System.currentTimeMillis()
    val notBefore = Date(now)
    val notAfter = Date(now + TimeUnit.DAYS.toMillis(365 * 5)) // 5-year validity
    val serial = BigInteger(64, SecureRandom())

    return JcaX509v3CertificateBuilder(X500Principal(issuerName), serial, notBefore, notAfter, X500Principal(subjectName), subjectKey)
  }

  private fun buildCertificatePolicies(): CertificatePolicies {
    val policyQualifierInfo1 = PolicyQualifierInfo("https://gemspec.gematik.de/docs/gemRL/gemRL_SMC-B_ORG_BP/latest/")
    val policyInfo1 = PolicyInformation(gematikPolicy, DERSequence(policyQualifierInfo1))
    val policyInfo2 = PolicyInformation(smcbAuth, null)

    return CertificatePolicies(arrayOf(policyInfo1, policyInfo2))
  }

  private fun buildAdmissionSyntax(): AdmissionSyntax {
    //    val namingAuthority =
    //      NamingAuthority(
    //        ASN1ObjectIdentifier("1.2.276.0.76.4.58"),
    //        "https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID",
    //        DirectoryString("gematik GmbH"),
    //      )
    val professionInfo = ProfessionInfo(null, arrayOf(DirectoryString(BETRIEBSSTAETTE_ARZT)), arrayOf(betriebsstaetteArzt), TELEMATIK_ID, null)

    // Per RFC 5755, admissionAuthority in AdmissionSyntax and Admissions
    // MUST NOT be present simultaneously. We will set it in the top-level
    // AdmissionSyntax, so we set it to null here.
    val admissionAuthority = GeneralName(X500Name(DN_GEMATIK))
    val admissions = Admissions(null, null, arrayOf(professionInfo))
    val contentsOfAdmissions = DERSequence(arrayOf(admissions))

    return AdmissionSyntax(admissionAuthority, contentsOfAdmissions)
  }
}
