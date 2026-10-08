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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.commons.server

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.raise.ensureNotNull
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import java.io.StringReader
import java.io.StringWriter
import java.security.Key
import java.security.PrivateKey
import java.security.PublicKey
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
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x500.style.BCStyle
import org.bouncycastle.asn1.x500.style.IETFUtils
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.openssl.jcajce.JcaPEMWriter
import org.keycloak.common.util.PemUtils

// https://oidref.com/1.3.36.8.3.3
val admission = ASN1ObjectIdentifier("1.3.36.8.3.3")

/**
 * Returns true if the certificate appears to be a self-signed root certificate.
 *
 * This checks two things:
 * 1) That the certificate's signature can be verified using its own public key (self-signed).
 * 2) That the certificate's key usage indicates certificate signing capability (keyUsage[5]).
 */
fun X509Certificate.isRoot(): Boolean {
  try {
    verify(publicKey)
    return keyUsage[5]
  } catch (_: Exception) {
    return false
  }
}

/**
 * Returns true if the certificate appears to be an intermediate CA certificate.
 *
 * Behavior:
 * - Attempts to verify the certificate using its own public key. If verification succeeds, it is considered a root (self-signed) and this function
 *   returns false.
 * - If verification throws a SignatureException with the specific message "certificate does not verify with supplied key", we interpret that as the
 *   certificate being signed by a different key (i.e. an intermediate) and return true.
 * - Any other exception will result in false.
 */
fun X509Certificate.isIntermediate(): Boolean {
  try {
    verify(publicKey)
    return false // is, root if signed with own private/public key
  } catch (e: SignatureException) {
    return e.message == "certificate does not verify with supplied key"
  }
}

/**
 * Encode this X.509 certificate to a base64 DER string.
 *
 * The underlying certificate's encoded form (ASN.1 DER) is base64-encoded and returned.
 */
fun X509Certificate.toDER() = encoded.toBase64()

/**
 * Encode a generic Key (for example a PrivateKey or PublicKey) to a base64 DER string.
 *
 * The key's encoded form is base64-encoded and returned.
 */
fun Key.toDER() = encoded.toBase64()

/**
 * Convert this X.509 certificate to a PEM formatted string.
 *
 * The returned string contains the standard PEM headers and base64 body for the certificate.
 */
fun X509Certificate.toPEM() = toPEMString()

/**
 * Convert this Key to a PEM formatted string.
 *
 * The returned string contains the standard PEM headers and base64 body for the certificate.
 */
fun Key.toPEM() = toPEMString()

/** Internal helper that writes any object understandable by BouncyCastle's JcaPEMWriter to a PEM string. */
private fun Any.toPEMString(): String {
  val out = StringWriter()
  JcaPEMWriter(out).use { it.writeObject(this@toPEMString) }
  return out.toString()
}

/** Validate that the provided certificate's signature was generated with the given public key. */
fun validateCertificateSignature(certificate: X509Certificate, publicKey: PublicKey): Either<String, Success> = either {
  Either.catch { certificate.verify(publicKey) }
      .mapLeft {
        logger.error("Signature validation failed for $certificate", it)
        it.message ?: "Signature validation failed"
      }
      .bind()

  SimpleSuccess
}

/**
 * Heuristically check whether the provided string contains a PEM object.
 *
 * Returns true when BouncyCastle's PEMParser can read at least one object from the string.
 */
fun String.isPEMFormat(): Boolean =
    try {
      PEMParser(StringReader(this)).use { it.readObject() != null }
    } catch (e: Exception) {
      false
    }

/**
 * Convert a string containing either a PEM-encoded certificate or a base64 DER certificate to an X509Certificate.
 *
 * Behavior:
 * - If the input is recognized as PEM, it uses Keycloak's PemUtils to decode it.
 * - Otherwise, the string is treated as base64-encoded DER and decoded via a CertificateFactory using the configured BouncyCastle provider.
 */
fun String.toCertificate(): X509Certificate =
    if (isPEMFormat()) {
      PemUtils.decodeCertificate(this)
    } else {
      fromBase64().toCertificate()
    }

fun ByteArray.toCertificate(): X509Certificate {
  val certificateFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME)

  return certificateFactory.generateCertificate(inputStream()) as X509Certificate
}

fun ByteArray.toPrivateKey(): PrivateKey {
  val privateKeyInfo = PrivateKeyInfo.getInstance(this)

  return JcaPEMKeyConverter().setProvider(PROVIDER_NAME).getPrivateKey(privateKeyInfo)
}

/**
 * Validate a certificate chain against a trust store provided by the KeystoreService.
 *
 * Process:
 * - Finds the first certificate in the provided chain that has an issuer present in the keystore_service.
 * - Validate against that certificate
 */
fun validateCertificateChain(keystoreService: KeystoreService, certificateChain: List<X509Certificate>): Either<String, PKIXCertPathValidatorResult> =
    either {
      val certificate = certificateChain.first { keystoreService.findIssuerCertificate(it) != null }

      ensureNotNull(certificate) { "No issuer certificate found in trust store" }

      val certificateIndex = certificateChain.indexOf(certificate)
      val chain = certificateChain.subList(0, certificateIndex + 1)
      val rootCertificate = keystoreService.findIssuerCertificate(certificate)!!

      validateCertificateChain(rootCertificate, chain).bind()
    }

/**
 * Validate a certificate chain against a provided root certificate (trust anchor).
 *
 * This function performs PKIX validation using the BouncyCastle provider with optional revocation checking.
 */
fun validateCertificateChain(rootCertificate: X509Certificate, certificateChain: List<X509Certificate>): Either<String, PKIXCertPathValidatorResult> =
    either {
      ensure(certificateChain.isNotEmpty()) { "Certificate chain is empty" }

      Either.catch {
            val certFactory = CertificateFactory.getInstance("X.509", PROVIDER_NAME)
            val certPath = certFactory.generateCertPath(certificateChain)
            val trustAnchor = TrustAnchor(rootCertificate, null)
            val params = PKIXParameters(setOf(trustAnchor)).apply { isRevocationEnabled = false } // check revocation as a later step
            val validator = CertPathValidator.getInstance("PKIX", PROVIDER_NAME)

            validator.validate(certPath, params) as PKIXCertPathValidatorResult
          }
          .mapLeft {
            logger.error("Certificate validation failed for ${certificateChain.toList()}", it)
            it.message ?: "Certificate validation failed"
          }
          .bind()
    }

/**
 * Extract a typed ASN.1 extension from this certificate using the provided OID.
 *
 * This helper uses BouncyCastle's JcaX509CertificateHolder to obtain the parsed extension.
 */
inline fun <reified T : ASN1Encodable> X509Certificate.extractExtension(oid: ASN1ObjectIdentifier): T? =
    try {
      val certHolder = JcaX509CertificateHolder(this)
      val encodable = certHolder.getExtension(oid)?.parsedValue

      T::class.members.find { it.name == "getInstance" }?.call(encodable) as T?
    } catch (e: Exception) {
      logger.warn("⚠️ Error parsing extension $oid: ${e.message}")
      null
    }

/** Return the first Admissions element contained in an AdmissionSyntax instance, or null if none exist. */
fun AdmissionSyntax.firstAdmission(): Admissions? = if (contentsOfAdmissions.isNotEmpty()) contentsOfAdmissions[0] else null

/** Return the first ProfessionInfo element contained in an Admissions instance, or null if none exist. */
fun Admissions.firstProfessionInfo(): ProfessionInfo? = if (professionInfos.isNotEmpty()) professionInfos[0] else null

/** Return the first profession OID contained in a ProfessionInfo instance, or null if none exist. */
fun ProfessionInfo.firstProfession(): ASN1ObjectIdentifier? = if (professionOIDs.isNotEmpty()) professionOIDs[0] else null

/** Convenience: extract the Common Name (CN) component from the certificate's subject DN. */
fun X509Certificate.subjectCommonName() = getSubjectComponent(BCStyle.CN)

/** Convenience: extract the Organization (O) component from the certificate's subject DN. */
fun X509Certificate.subjectOrganisationName() = getSubjectComponent(BCStyle.O)

/** Internal helper to extract a single subject component value from this certificate's subject DN using the provided ASN.1 identifier. */
private fun X509Certificate.getSubjectComponent(identifier: ASN1ObjectIdentifier) =
    X500Name(subjectX500Principal.name).getRDNs(identifier).map { IETFUtils.valueToString(it.first.value) }.firstOrNull() ?: "Unbekannt"
