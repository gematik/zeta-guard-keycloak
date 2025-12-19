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

package de.gematik.zeta.zetaguard.keycloak.commons.server

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import java.io.StringWriter
import java.security.Key
import java.security.PublicKey
import java.security.Security
import java.security.SignatureException
import java.security.cert.CertPathValidator
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.isismtt.x509.AdmissionSyntax
import org.bouncycastle.asn1.isismtt.x509.Admissions
import org.bouncycastle.asn1.isismtt.x509.ProfessionInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.openssl.jcajce.JcaPEMWriter

const val CRT_GEMATIK_ROOT = "gem.smcb-ca1_test-only"
const val CRT_GEMATIK_ROOT_DN = "CN=GEM.RCA1 TEST-ONLY, OU=Zentrale Root-CA der Telematikinfrastruktur, O=gematik GmbH NOT-VALID, C=DE"
const val CRT_GEMATIK_INTERMEDIATE = "gem.smcb-ca57_test-only"
const val CRT_GEMATIK_LEAF = "zeta.c_smcb_aut"
const val CRT_GEMATIK_LEAF_NAME = "Arztpraxis Ann-Beatrixe Zeta TEST-ONLY"
const val CRT_GEMATIK_LEAF_ORGANISATION = "300060625 NOT-VALID"
const val CRT_GEMATIK_LEAF_DN = "C=DE, O=$CRT_GEMATIK_LEAF_ORGANISATION, CN=$CRT_GEMATIK_LEAF_NAME"

// https://oidref.com/1.3.36.8.3.3
val admission = ASN1ObjectIdentifier("1.3.36.8.3.3")

// https://gemspec.gematik.de/downloads/gemSpec/gemSpec_OID/gemSpec_OID_V3.12.3_Aend.html#3.5.1.3
val betriebsstaetteArzt = ASN1ObjectIdentifier("1.2.276.0.76.4.50")
val gematikPolicy = ASN1ObjectIdentifier("1.2.276.0.76.4.163")
val smcbAuth = ASN1ObjectIdentifier("1.2.276.0.76.4.77")

const val BETRIEBSSTAETTE_ARZT = "Betriebsstätte Arzt"

fun X509Certificate.isRoot(): Boolean {
  try {
    verify(publicKey)
    return keyUsage[5]
  } catch (_: Exception) {
    return false
  }
}

fun X509Certificate.isIntermediate(): Boolean {
  try {
    verify(publicKey)
    return false // is, root if signed with own private/public key
  } catch (e: SignatureException) {
    return e.message == "certificate does not verify with supplied key"
  }
}

fun X509Certificate.toPEM() = toPEMString()

fun Key.toPEM() = toPEMString()

private fun Any.toPEMString(): String {
  val out = StringWriter()
  JcaPEMWriter(out).use { it.writeObject(this@toPEMString) }
  return out.toString()
}

fun validateCertificateSignature(certificate: X509Certificate, publicKey: PublicKey): Either<String, Success> = either {
  Either.catch { certificate.verify(publicKey) }
      .mapLeft {
        logger.error("Signature validation failed for $certificate", it)
        it.message ?: "Signature validation failed"
      }
      .bind()

  SimpleSuccess
}

fun validateCertificateChain(
    rootCertificate: X509Certificate,
    vararg certificateChain: X509Certificate,
): Either<String, PKIXCertPathValidatorResult> = either {
  ensure(certificateChain.isNotEmpty()) { "Certificate chain is empty" }

  Either.catch {
        val certFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME)
        val chainToValidate = listOf(*certificateChain)
        val certPath = certFactory.generateCertPath(chainToValidate)
        val trustAnchor = TrustAnchor(rootCertificate, null)
        val params = PKIXParameters(setOf(trustAnchor)).apply { isRevocationEnabled = false }
        val validator = CertPathValidator.getInstance("PKIX", PROVIDER_NAME)

        validator.validate(certPath, params) as PKIXCertPathValidatorResult
      }
      .mapLeft {
        logger.error("Certificate validation failed for ${certificateChain.toList()}", it)
        it.message ?: "Certificate validation failed"
      }
      .bind()
}

inline fun <reified T : ASN1Encodable> X509Certificate.extractExtension(oid: ASN1ObjectIdentifier): T? =
    try {
      val certHolder = JcaX509CertificateHolder(this)
      val encodable = certHolder.getExtension(oid)?.parsedValue

      T::class.members.find { it.name == "getInstance" }?.call(encodable) as T?
    } catch (e: Exception) {
      logger.warn("Error parsing extension $oid: ${e.message}")
      null
    }

fun AdmissionSyntax.firstAdmission(): Admissions? = if (contentsOfAdmissions.isNotEmpty()) contentsOfAdmissions[0] else null

fun Admissions.firstProfessionInfo(): ProfessionInfo? = if (professionInfos.isNotEmpty()) professionInfos[0] else null

fun ProfessionInfo.firstProfession(): ASN1ObjectIdentifier? = if (professionOIDs.isNotEmpty()) professionOIDs[0] else null

fun X509Certificate.subjectCommonName() = getSubjectComponent(BCStyle.CN)

fun X509Certificate.subjectOrganisationName() = getSubjectComponent(BCStyle.O)

private fun X509Certificate.getSubjectComponent(identifier: ASN1ObjectIdentifier) =
    X500Name(subjectX500Principal.name).getRDNs(identifier).map { IETFUtils.valueToString(it.first.value) }.firstOrNull() ?: "Unbekannt"

fun setupBouncyCastle() {
  val indexOfBC1 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }

  when (indexOfBC1) {
    0 -> {
      logger.info("BouncyCastle is set as default security provider")
      return
    }

    -1 -> {
      logger.info("BouncyCastle not found in list")
    }

    else -> {
      logger.info("BouncyCastle found in list, but is not the default security provider")
      Security.removeProvider(PROVIDER_NAME)
    }
  }

  val indexOfBC2 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }
  assert(indexOfBC2 < 0) { "BC provider still present in list!" }

  logger.info("Setting BouncyCastle as default security provider")

  Security.insertProviderAt(BouncyCastleProvider(), 1)

  val indexOfBC3 = Security.getProviders().indexOfFirst { it.name == PROVIDER_NAME }
  assert(indexOfBC3 == 0) { "BC provider is still not the default security provider!" }
}
