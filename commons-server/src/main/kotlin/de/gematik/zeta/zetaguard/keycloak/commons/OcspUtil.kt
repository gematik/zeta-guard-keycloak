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

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.left
import arrow.core.raise.either
import arrow.core.raise.ensure
import arrow.core.right
import com.google.common.cache.CacheBuilder
import de.gematik.zeta.zetaguard.keycloak.commons.server.extractExtension
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreMetaService
import java.io.IOException
import java.net.URI
import java.security.MessageDigest
import java.security.cert.X509Certificate
import java.text.SimpleDateFormat
import java.time.Duration
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.util.EntityUtils
import org.bouncycastle.asn1.DERIA5String
import org.bouncycastle.asn1.isismtt.ISISMTTObjectIdentifiers
import org.bouncycastle.asn1.isismtt.ocsp.CertHash
import org.bouncycastle.asn1.x509.AccessDescription
import org.bouncycastle.asn1.x509.AuthorityInformationAccess
import org.bouncycastle.asn1.x509.CRLReason
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.GeneralName
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.ocsp.BasicOCSPResp
import org.bouncycastle.cert.ocsp.CertificateID
import org.bouncycastle.cert.ocsp.CertificateStatus
import org.bouncycastle.cert.ocsp.OCSPReqBuilder
import org.bouncycastle.cert.ocsp.OCSPResp
import org.bouncycastle.cert.ocsp.RevokedStatus
import org.bouncycastle.cert.ocsp.SingleResp
import org.bouncycastle.cert.ocsp.UnknownStatus
import org.bouncycastle.cert.ocsp.jcajce.JcaCertificateID
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder
import org.keycloak.common.util.BouncyIntegration

sealed class CertStatus {
  object Good : CertStatus()

  object Unknown : CertStatus()

  data class Revoked(val since: Date, val reason: String) : CertStatus()
}

object OcspUtil {
  internal val MAX_EXPIRES = Duration.ofHours(24)
  internal const val UNAVAILABLE_EXPIRY_MS = 60000L // 1 minute
  internal const val CLOCK_SKEW_MS = 37500L // 37.5s according to GS-A_5215
  const val DEFAULT_CONNECT_TIMEOUT_MS = 1000
  const val DEFAULT_READ_TIMEOUT_MS = 3000
  const val DEFAULT_FAIL_CLOSED = false

  private data class StatusEntry(val status: CertStatus, val from: Date, val until: Date)

  private val cache = CacheBuilder.newBuilder().expireAfterWrite(MAX_EXPIRES).build<CertificateID, StatusEntry>()

  fun clearCache() = cache.invalidateAll()

  fun checkRevoked(
      certificate: X509Certificate,
      issuers: KeystoreMetaService,
      signers: KeystoreMetaService?,
      httpClient: CloseableHttpClient,
      checkDate: Date = Date(),
      config: OcspConfig = OcspConfig(),
  ): Either<String, CertStatus> =
      if (signers == null) {
        // OCSP disabled without signer store
        CertStatus.Unknown.right()
      } else {
        getStatus(certificate, issuers, signers, checkDate, httpClient, config).flatMap {
          when (it) {
            is CertStatus.Revoked -> "Certificate has been revoked since ${rfcTime.format(it.since)} for ${it.reason}".left()
            CertStatus.Unknown -> if (config.failClosed) "OCSP revocation status could not be determined".left() else it.right()
            CertStatus.Good -> it.right()
          }
        }
      }
          .onLeft { logger.error("OCSP revocation check failed for ${certificate.subjectX500Principal}") }

  private fun getStatus(
      certificate: X509Certificate,
      issuers: KeystoreMetaService,
      signers: KeystoreMetaService,
      checkDate: Date,
      httpClient: CloseableHttpClient,
      config: OcspConfig,
  ): Either<String, CertStatus> = either {
    logger.debug("Check revocation of ${certificate.subjectX500Principal}")

    val issuer = issuers.findIssuerCertificate(certificate)
    ensure(issuer != null) { "could not determine issuer certificate" }
    val x = issuers.getRevokedSince(issuer)
    x?.takeIf { certificate.notBefore.after(it) }
        ?.let {
          return CertStatus.Revoked(it, "issued after CA revocation").right()
        }

    val sha1 = JcaDigestCalculatorProviderBuilder().build()[CertificateID.HASH_SHA1]
    val certId = JcaCertificateID(sha1, issuer, certificate.serialNumber)
    val uri = getResponderURL(certificate) ?: raise("no responder URI in certificate")
    val cached = cache.getIfPresent(certId)

    if (cached != null && !isOutdated(cached.from, cached.until, checkDate)) {
      logger.debug("OCSP response in cache for ${certificate.subjectX500Principal}")

      return cached.status.right()
    }

    val outer = retrieveResponse(certId, uri, httpClient, config).bind()

    if (outer == null) {
      cache.put(certId, StatusEntry(CertStatus.Unknown, checkDate, Date(checkDate.time + UNAVAILABLE_EXPIRY_MS)))
      return CertStatus.Unknown.right()
    }

    val single = verifyBasicResponse(outer, issuer, issuers, signers).bind()
    verifySingleResponse(single, certId, checkDate).bind()
    verifyCertHash(single, certificate).bind()

    val status = convertStatus(single.certStatus).bind()

    cache.put(certId, StatusEntry(status, single.thisUpdate, single.nextUpdate ?: Date(single.thisUpdate.time + MAX_EXPIRES.toMillis())))

    return status.right()
  }

  private fun getResponderURL(certificate: X509Certificate): URI? =
      certificate
          .extractExtension<AuthorityInformationAccess>(Extension.authorityInfoAccess)
          ?.accessDescriptions
          ?.first { access ->
            access.accessMethod == AccessDescription.id_ad_ocsp && access.accessLocation.tagNo == GeneralName.uniformResourceIdentifier
          }
          ?.accessLocation
          ?.let { location -> URI((location.name as DERIA5String).string) }

  private fun isOutdated(from: Date, until: Date?, checkDate: Date): Boolean =
      before(checkDate, from) || (until != null && after(checkDate, until)) || between(from, checkDate) >= MAX_EXPIRES

  private fun before(a: Date, b: Date) = a.time < b.time - CLOCK_SKEW_MS

  private fun after(a: Date, b: Date) = a.time > b.time + CLOCK_SKEW_MS

  private fun between(a: Date, b: Date) = Duration.ofMillis(b.time - a.time - CLOCK_SKEW_MS)

  private fun retrieveResponse(
      certId: CertificateID,
      uri: URI,
      httpClient: CloseableHttpClient,
      config: OcspConfig,
  ): Either<String, OCSPResp?> =
      either {
        logger.debug("OCSP request using responder $uri")
        val ocspReq = Either.catch { OCSPReqBuilder().addRequest(certId).build() }.bind()
        val ocspResp = getEncodedOCSPResponse(ocspReq.encoded, uri, httpClient, config).bind()
        Either.catch { OCSPResp(ocspResp) }.bind()
      }
          .fold(
              ifLeft = { throwable ->
                when (throwable) {
                  is IOException -> {
                    logger.warn("OCSP request failed, response not available: ${throwable.message}")
                    null.right() // unavailable
                  }

                  else -> (throwable.message ?: "Error during OCSP request").left()
                }
              },
              ifRight = { resp ->
                logger.debug("Received an OCSP response from $uri with status ${resp.status}")
                when (resp.status) {
                  0 -> resp.right()
                  2,
                  3 -> {
                    logger.info("Internal error/try later. OCSP response error: ${resp.status}")
                    null.right() // unavailable
                  }

                  5 -> "Invalid or missing signature. OCSP response error: ${resp.status}".left()
                  6 -> "Unauthorized request. OCSP response error: ${resp.status}".left()
                  else -> "OCSP request is malformed. OCSP response error: ${resp.status}".left()
                }
              },
          )

  private fun getEncodedOCSPResponse(
      encodedOCSPReq: ByteArray,
      responderURI: URI,
      httpClient: CloseableHttpClient,
      config: OcspConfig,
  ): Either<Throwable, ByteArray> =
      Either.catch {
        val requestConfig =
            RequestConfig.custom()
                .setConnectTimeout(config.connectTimeoutMs)
                .setConnectionRequestTimeout(config.connectTimeoutMs)
                .setSocketTimeout(config.readTimeoutMs)
                .build()
        HttpPost(responderURI)
            .apply {
              setHeader("Content-Type", "application/ocsp-request")
              entity = ByteArrayEntity(encodedOCSPReq)
              this.config = requestConfig
            }
            .let { httpClient.execute(it) }
      }
          .flatMap { response ->
            response.use { resp ->
              when (val statusCode = resp.statusLine.statusCode) {
                200 -> EntityUtils.toByteArray(resp.entity).right()
                else ->
                  IOException("Connection error, unable to obtain revocation status from OCSP responder \"$responderURI\", code $statusCode\"")
                      .left()
              }
            }
          }

  private fun verifyBasicResponse(
      outer: OCSPResp,
      issuer: X509Certificate,
      issuers: KeystoreMetaService,
      signers: KeystoreMetaService,
  ): Either<String, SingleResp> {
    // ensure correct content
    if (outer.responseObject !is BasicOCSPResp) {
      return "OCSP responder returned an invalid OCSP response.".left()
    }
    val resp = outer.responseObject as BasicOCSPResp

    // ensure expected structure
    if (resp.responses == null || resp.responses.size != 1) {
      return "OCSP responder returned an incomplete response.".left()
    }
    if (resp.certs == null || resp.certs.size < 1) {
      return "OCSP responder did not provide a signer certificate.".left()
    }

    // verify signature
    val signer = JcaX509CertificateConverter().setProvider(BouncyIntegration.PROVIDER).getCertificate(resp.certs[0])
    val verifier = JcaContentVerifierProviderBuilder().setProvider(BouncyIntegration.PROVIDER).build(signer.publicKey)
    if (!resp.isSignatureValid(verifier)) {
      return "OCSP response signature is invalid!".left()
    }

    // ensure signer is trusted
    if (!signers.hasCertificate(signer)) {
      return "OCSP signer is not trusted: ${signer.subjectX500Principal}".left()
    }

    // ensure signer and issuer belong to the same TSP
    issuers.getTsp(issuer)?.let { issuerTsp ->
      val signerTsp = signers.getTsp(signer)
      if (issuerTsp != signerTsp) {
        return "OCSP signer TSP '$signerTsp' does not match issuer TSP '$issuerTsp'".left()
      }
    }

    return resp.responses[0].right()
  }

  private fun verifySingleResponse(single: SingleResp, certId: CertificateID, checkDate: Date): Either<String, Unit> {
    if (single.certID != certId) {
      return "OCSP response does not match request.".left()
    }
    if (isOutdated(single.thisUpdate, single.nextUpdate, checkDate)) {
      return "OCSP response is out of date.".left()
    }
    return Unit.right()
  }

  private fun verifyCertHash(single: SingleResp, certificate: X509Certificate): Either<String, Unit> {
    val certHash = single.getExtension(ISISMTTObjectIdentifiers.id_isismtt_at_certHash)
    if (certHash == null) {
      if (single.certStatus == CertificateStatus.GOOD) {
        return "OCSP response does not contain the required CertHash extension.".left()
      }
    } else {
      val expectedHash = MessageDigest.getInstance("SHA-256").digest(certificate.encoded)
      val providedHash = CertHash.getInstance(certHash.parsedValue).certificateHash
      if (!providedHash.contentEquals(expectedHash)) {
        return "OCSP CertHash does not match the original certificate.".left()
      }
    }
    return Unit.right()
  }

  private fun convertStatus(status: CertificateStatus?): Either<String, CertStatus> =
      when (status) {
        CertificateStatus.GOOD -> CertStatus.Good.right()
        is UnknownStatus -> CertStatus.Unknown.right()
        is RevokedStatus -> {
          val reason =
              if (status.hasRevocationReason()) {
                CRLReason.lookup(status.revocationReason)
              } else {
                CRLReason.lookup(CRLReason.unspecified)
              }
          CertStatus.Revoked(status.revocationTime, reason.toString()).right()
        }

        else -> "unknown type of certificate status: ${status!!.javaClass.name}".left()
      }

  private val rfcTime = SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss 'GMT'", Locale.US).apply { timeZone = TimeZone.getTimeZone("UTC") }
}
