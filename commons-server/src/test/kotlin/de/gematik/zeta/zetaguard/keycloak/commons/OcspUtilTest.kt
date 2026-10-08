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

import de.gematik.zeta.zetaguard.keycloak.commons.OcspUtil.CLOCK_SKEW_MS
import de.gematik.zeta.zetaguard.keycloak.commons.OcspUtil.MAX_EXPIRES
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreMetaService
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.clearMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.slot
import io.mockk.verify
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date
import org.apache.http.HttpVersion
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ByteArrayEntity
import org.apache.http.entity.ContentType
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.message.BasicHttpResponse
import org.apache.http.message.BasicStatusLine
import org.bouncycastle.util.encoders.Base64

class OcspUtilTest : ZetaGuardFunSpec() {
  init {

    val httpClient = mockk<CloseableHttpClient>(relaxed = true)
    val signers = mockk<KeystoreMetaService>()
    val issuers = mockk<KeystoreMetaService>()

    beforeTest {
      OcspUtil.clearCache()
      clearMocks(httpClient)
      clearMocks(signers)
      every { signers.hasCertificate(any<X509Certificate>()) } returns true
      every { signers.getTsp(any()) } returns "gematik"
      clearMocks(issuers)
      every { issuers.getRevokedSince(any()) } returns null
      every { issuers.getTsp(any()) } returns "gematik"
    }

    test("disabled") {
      val result = OcspUtil.checkRevoked(praxisRevoked, issuers, null, httpClient, praxisRevokedDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Unknown
    }

    test("unknown issuer") {
      every { issuers.findIssuerCertificate(any()) } returns null

      val result = OcspUtil.checkRevoked(praxisRevoked, issuers, signers, httpClient, praxisRevokedDate)
      var error = result.shouldBeLeft()
      error shouldContain "could not determine issuer"
    }

    test("revoked") {
      every { issuers.findIssuerCertificate(praxisRevoked) } returns praxisRevokedIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, praxisRevokedResponse)

      val result = OcspUtil.checkRevoked(praxisRevoked, issuers, signers, httpClient, praxisRevokedDate)
      var error = result.shouldBeLeft()
      error shouldContain "Certificate has been revoked"
    }

    test("good") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good
    }

    test("request timeout applied") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      val request = slot<HttpPost>()
      every { httpClient.execute(capture(request)) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate, config = OcspConfig(connectTimeoutMs = 1234, readTimeoutMs = 5678))
      result.shouldBeRight() shouldBe CertStatus.Good

      val config = request.captured.config
      config.connectTimeout shouldBe 1234
      config.connectionRequestTimeout shouldBe 1234
      config.socketTimeout shouldBe 5678
    }

    test("after CA revoked") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { issuers.getRevokedSince(guardGoodIssuer) } returns Date(guardGood.notBefore.time - 1L) // revoked before cert

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var error = result.shouldBeLeft()
      error shouldContain "issued after CA revocation"
    }

    test("before CA revoked") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { issuers.getRevokedSince(guardGoodIssuer) } returns Date(guardGood.notBefore.time + 1L) // revoked after cert
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good
    }

    test("cached response") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good

      val result2 = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status2 = result2.shouldBeRight()
      status2 shouldBe CertStatus.Good

      verify(exactly = 1) { httpClient.execute(any<HttpPost>()) }
    }

    test("no response fails closed when failClosed=true") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(400, ByteArray(0))

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate, config = OcspConfig(failClosed = true))
      var error = result.shouldBeLeft()
      error shouldContain "could not be determined"
    }

    test("malformed response fails closed when failClosed=true") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, ByteArray(0))

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate, config = OcspConfig(failClosed = true))
      var error = result.shouldBeLeft()
      error shouldContain "could not be determined"
    }

    test("unreachable responder fails closed when failClosed=true") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } throws IOException("Connection timed out")

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate, config = OcspConfig(failClosed = true))
      var error = result.shouldBeLeft()
      error shouldContain "could not be determined"
    }

    test("unreachable responder allowed by default (fail-open)") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } throws IOException("Connection timed out")

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Unknown
    }

    test("no response allowed by default (fail-open)") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(400, ByteArray(0))

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Unknown
    }

    test("malformed response allowed by default (fail-open)") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, ByteArray(0))

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Unknown
    }

    test("revoked denied even in fail-open (default)") {
      every { issuers.findIssuerCertificate(praxisRevoked) } returns praxisRevokedIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, praxisRevokedResponse)

      val result = OcspUtil.checkRevoked(praxisRevoked, issuers, signers, httpClient, praxisRevokedDate, config = OcspConfig(failClosed = false))
      var error = result.shouldBeLeft()
      error shouldContain "Certificate has been revoked"
    }

    test("certID mismatch") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, praxisRevokedResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var error = result.shouldBeLeft()
      error shouldContain "response does not match request"
    }

    test("too new") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, Date(Long.MIN_VALUE))
      var error = result.shouldBeLeft()
      error shouldContain "response is out of date"
    }

    test("too old") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, Date(Long.MAX_VALUE))
      var error = result.shouldBeLeft()
      error shouldContain "response is out of date"
    }

    test("early clock skew") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val responseTime = Date(1780401940000L - 1L) // 1ms before thisUpdate in response
      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, responseTime)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good

      val responseTime2 = Date(1780401940000L - CLOCK_SKEW_MS - 1L) // 1ms before thisUpdate minus clock skew
      val result2 = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, responseTime2)
      var error2 = result2.shouldBeLeft()
      error2 shouldContain "response is out of date"
    }

    test("late clock skew") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)

      val responseTime = Date(1780401940000L + MAX_EXPIRES.toMillis() + 1L) // 1ms after thisUpdate plus max duration
      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, responseTime)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good

      val responseTime2 = Date(1780401940000L + MAX_EXPIRES.toMillis() + CLOCK_SKEW_MS + 1L) // 1ms after thisUpdate plus max duration and clock skew
      val result2 = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, responseTime2)
      var error2 = result2.shouldBeLeft()
      error2 shouldContain "response is out of date"
    }

    test("signer not trusted") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)
      every { signers.hasCertificate(any<X509Certificate>()) } returns false

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var error = result.shouldBeLeft()
      error shouldContain "signer is not trusted"
    }

    test("TSP match") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)
      every { issuers.getTsp(any()) } returns "gematik"
      every { signers.getTsp(any()) } returns "gematik"

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var status = result.shouldBeRight()
      status shouldBe CertStatus.Good
    }

    test("TSP mismatch") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)
      every { issuers.getTsp(any()) } returns "gematik"
      every { signers.getTsp(any()) } returns "invalid"

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var error = result.shouldBeLeft()
      error shouldContain "does not match issuer TSP"
    }

    test("TSP unknown") {
      every { issuers.findIssuerCertificate(any()) } returns guardGoodIssuer
      every { httpClient.execute(any<HttpPost>()) } returns FakeHttp(200, guardGoodResponse)
      every { issuers.getTsp(any()) } returns "gematik"
      every { signers.getTsp(any()) } returns null

      val result = OcspUtil.checkRevoked(guardGood, issuers, signers, httpClient, guardGoodDate)
      var error = result.shouldBeLeft()
      error shouldContain "does not match issuer TSP"
    }
  }

  val praxisRevoked =
      parseCertificate(
          """
            MIIDNDCCAtugAwIBAgIHAlD+GrgMnjAKBggqhkjOPQQDAjCBlTELMAkGA1UEBhMC
            REUxGjAYBgNVBAoMEWdlbWF0aWsgTk9ULVZBTElEMUgwRgYDVQQLDD9JbnN0aXR1
            dGlvbiBkZXMgR2VzdW5kaGVpdHN3ZXNlbnMtQ0EgZGVyIFRlbGVtYXRpa2luZnJh
            c3RydWt0dXIxIDAeBgNVBAMMF0dFTS5TTUNCLUNBNTcgVEVTVC1PTkxZMB4XDTI1
            MDYwNTIyMDAwMFoXDTMwMDYwNTIxNTk1OVowXDELMAkGA1UEBhMCREUxHDAaBgNV
            BAoMEzMwMDA2MDYyNSBOT1QtVkFMSUQxLzAtBgNVBAMMJkFyenRwcmF4aXMgQW5u
            LUJlYXRyaXhlIFpldGEgVEVTVC1PTkxZMFowFAYHKoZIzj0CAQYJKyQDAwIIAQEH
            A0IABFQuEkLCX5kJcWaGYXdaRTdTAjAhEkDl9CWWd8vFHYGShmjhcFhm5bIex4R3
            JEqghvkP0fJgzgo9AzAauRLzZDGjggFLMIIBRzAOBgNVHQ8BAf8EBAMCB4AwDAYD
            VR0TAQH/BAIwADAsBgNVHR8EJTAjMCGgH6AdhhtodHRwOi8vZWhjYS5nZW1hdGlr
            LmRlL2NybC8wRQYFKyQIAwMEPDA6MDgwNjA0MDIwFgwUQmV0cmllYnNzdMOkdHRl
            IEFyenQwCQYHKoIUAEwEMhMNMS0yMDAxNDA2MDYyNTAdBgNVHQ4EFgQUPx8Y1o6A
            SAn/4iiWV168PmCrKzMwEwYDVR0lBAwwCgYIKwYBBQUHAwIwIAYDVR0gBBkwFzAK
            BggqghQATASBIzAJBgcqghQATARNMB8GA1UdIwQYMBaAFLXvdX6ZmhfJ03cvWxHF
            hDMvBZxRMDsGCCsGAQUFBwEBBC8wLTArBggrBgEFBQcwAYYfaHR0cDovL2VoY2Eu
            Z2VtYXRpay5kZS9lY2Mtb2NzcDAKBggqhkjOPQQDAgNHADBEAiAWFykxDcPK8au6
            QUrkgmpg59mGEoignIPE/+/jEyDlCgIgZBWQB/ASGePjrYWaieIxzCi1+wEBqjVP
            Q83x7DOZDuA=
          """
              .trimIndent()
      )

  val praxisRevokedIssuer =
      parseCertificate(
          """
            MIIDAzCCAqqgAwIBAgIBGzAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAd
            BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
            IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdF
            TS5SQ0E4IFRFU1QtT05MWTAeFw0yNDEwMjkxMzU0NTdaFw0zMjEwMjcxMzU0NTZa
            MIGVMQswCQYDVQQGEwJERTEaMBgGA1UECgwRZ2VtYXRpayBOT1QtVkFMSUQxSDBG
            BgNVBAsMP0luc3RpdHV0aW9uIGRlcyBHZXN1bmRoZWl0c3dlc2Vucy1DQSBkZXIg
            VGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLlNNQ0ItQ0E1NyBU
            RVNULU9OTFkwWjAUBgcqhkjOPQIBBgkrJAMDAggBAQcDQgAECUe8bf0PnfXFqf5x
            9kthnu3HX85akJUv5kUQ5VTFsoKTKeL6GJhKB5FphiV8TyeDFhzK2/hqbnAvBq4j
            Dv/L6qOB+zCB+DAdBgNVHQ4EFgQUte91fpmaF8nTdy9bEcWEMy8FnFEwHwYDVR0j
            BBgwFoAUobkUOicwe1xnHvUyxLHVGon8vFMwSgYIKwYBBQUHAQEEPjA8MDoGCCsG
            AQUFBzABhi5odHRwOi8vb2NzcC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5k
            ZS9vY3NwMA4GA1UdDwEB/wQEAwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8w
            LQYIKwYBBQUHAgEWIWh0dHA6Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczAS
            BgNVHRMBAf8ECDAGAQH/AgEAMAoGCCqGSM49BAMCA0cAMEQCIEUoM6GzqYvsZUj6
            9Ay3gSHORHqkYqE+BpBpG4M33EPTAiBjg8hLsboq/ViJSaScQsaCgVvfwiHzZl0d
            C4V+Ydzldg==
          """
              .trimIndent()
      )

  val praxisRevokedDate = Date(1779263728000L) // May 20 7:55:28 2026 GMT

  val praxisRevokedResponse: ByteArray =
      Base64.decode(
          """
            MIIEdgoBAKCCBG8wggRrBgkrBgEFBQcwAQEEggRcMIIEWDCCAVihVzBVMQswCQYDVQQGEwJERTEa
            MBgGA1UECgwRZ2VtYXRpayBOT1QtVkFMSUQxKjAoBgNVBAMMIWVoY2EgT0NTUCBTaWduZXIgNTEg
            ZWNjIFRFU1QtT05MWRgPMjAyNjA1MjAwNzU1MjhaMIHHMIHEMEAwCQYFKw4DAhoFAAQUGHYoQCnf
            EE+7ZfaMivYrbojg18sEFLXvdX6ZmhfJ03cvWxHFhDMvBZxRAgcCUP4auAyeoREYDzIwMjYwMTI2
            MTIyNDQ3WhgPMjAyNjA1MjAwNzU1MjhaoVwwWjAaBgUrJAgDDAQRGA8yMDI1MDYwNjA2NDc1Nlow
            PAYFKyQIAw0EMzAxMA0GCWCGSAFlAwQCAQUABCDDrb3XkiIvmjVSCPgKwaji3URvCrTHxvnulVp6
            76PNqqEiMCAwHgYJKwYBBQUHMAEGBBEYDzE4NzAwMTA3MDAwMDAwWjAKBggqhkjOPQQDAgNHADBE
            AiBAFlsyUnfjA+KjXS1+PDdj55ZGPL+3bmoEpmNma5DmcgIgO5pe425XJAo85fLZixmuEpj+RSyF
            O2yRei2k95iN+DSgggKjMIICnzCCApswggJBoAMCAQICBwLGdpbwXhYwCgYIKoZIzj0EAwIwgYQx
            CzAJBgNVBAYTAkRFMR8wHQYDVQQKDBZnZW1hdGlrIEdtYkggTk9ULVZBTElEMTIwMAYDVQQLDClL
            b21wb25lbnRlbi1DQSBkZXIgVGVsZW1hdGlraW5mcmFzdHJ1a3R1cjEgMB4GA1UEAwwXR0VNLktP
            TVAtQ0E1MSBURVNULU9OTFkwHhcNMjMwODI1MDAwMDAwWhcNMjgwODI1MjM1OTU5WjBVMQswCQYD
            VQQGEwJERTEaMBgGA1UECgwRZ2VtYXRpayBOT1QtVkFMSUQxKjAoBgNVBAMMIWVoY2EgT0NTUCBT
            aWduZXIgNTEgZWNjIFRFU1QtT05MWTBaMBQGByqGSM49AgEGCSskAwMCCAEBBwNCAAQwqcZgoJda
            2D7SO6XTgjccMoFQE6bMcx4YLf3svdbGN3UrBjBPQYY4vdw18cyv96ukOkwKzuR1EtaMvbqzlrmC
            o4HKMIHHMBUGA1UdIAQOMAwwCgYIKoIUAEwEgSMwEwYDVR0lBAwwCgYIKwYBBQUHAwkwOwYIKwYB
            BQUHAQEELzAtMCsGCCsGAQUFBzABhh9odHRwOi8vZWhjYS5nZW1hdGlrLmRlL2VjYy1vY3NwMA4G
            A1UdDwEB/wQEAwIGQDAfBgNVHSMEGDAWgBRilbvuRtkqL/LpyMxslyTUVZUxdzAdBgNVHQ4EFgQU
            x8I+ehCK6KuJR7cIHO7aHzWx+cgwDAYDVR0TAQH/BAIwADAKBggqhkjOPQQDAgNIADBFAiB/MdQi
            Hfkger1OqY5tuAMMVR/WoJNIRckfBJq5K2ns8gIhAI51ATrtqyN3/LxhcGoejGZSLO1D0nn5eFjS
            CraXAIh3
          """
              .trimIndent()
      )

  val guardGood =
      parseCertificate(
          """
            MIIC0TCCAnagAwIBAgIHAtIwvM27BzAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMC
            REUxHzAdBgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxMjAwBgNVBAsMKUtv
            bXBvbmVudGVuLUNBIGRlciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQD
            DBdHRU0uS09NUC1DQTYxIFRFU1QtT05MWTAeFw0yNjAyMjUyMzAwMDBaFw0zMTAy
            MjUyMjU5NTlaMGQxCzAJBgNVBAYTAkRFMSYwJAYDVQQKDB1nZW1hdGlrIFRFU1Qt
            T05MWSAtIE5PVC1WQUxJRDEtMCsGA1UEAwwkemV0YS1ndWFyZC5nZW1hdGlrLnRl
            bGVtYXRpay10ZXN0IDAxMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcLOSGfdJ
            hDRBmFe/X1vuIYYC+7MKmqKqI3dLSbhM8jECGRES7+xXfNkVXrCdHh/HQuxufL2M
            EgAY+LQLzqSDm6OB8TCB7jAOBgNVHQ8BAf8EBAMCB4AwPAYIKwYBBQUHAQEEMDAu
            MCwGCCsGAQUFBzABhiBodHRwOi8vZWhjYS5nZW1hdGlrLmRlL25pc3Qtb2NzcDAh
            BgNVHSAEGjAYMAoGCCqCFABMBIEjMAoGCCqCFABMBIEbMB8GA1UdIwQYMBaAFJ81
            4DCpf8r4Zp+QCkLNu4Fln0n+MC0GBSskCAMDBCQwIjAgMB4wHDAaMAwMClpFVEEg
            R3VhcmQwCgYIKoIUAEwEgkgwHQYDVR0OBBYEFDxIpIvcLB4uA+9U5we1IpJwYgM1
            MAwGA1UdEwEB/wQCMAAwCgYIKoZIzj0EAwIDSQAwRgIhAJAH47ZIuJGW5h0xUeuh
            PybKnZmaqts35UTrg0tOneZIAiEAzKSt3W++R1kxoRSRrd3t958YtQu+AMRM4gEh
            V4CZz1A=
          """
              .trimIndent()
      )

  val guardGoodIssuer =
      parseCertificate(
          """
            MIIC8TCCApigAwIBAgIBCzAKBggqhkjOPQQDAjCBgTELMAkGA1UEBhMCREUxHzAd
            BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxNDAyBgNVBAsMK1plbnRyYWxl
            IFJvb3QtQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3RydWt0dXIxGzAZBgNVBAMMEkdF
            TS5SQ0E3IFRFU1QtT05MWTAeFw0yMzA3MTgxMjAyNTVaFw0zMTA3MTYxMjAyNTRa
            MIGEMQswCQYDVQQGEwJERTEfMB0GA1UECgwWZ2VtYXRpayBHbWJIIE5PVC1WQUxJ
            RDEyMDAGA1UECwwpS29tcG9uZW50ZW4tQ0EgZGVyIFRlbGVtYXRpa2luZnJhc3Ry
            dWt0dXIxIDAeBgNVBAMMF0dFTS5LT01QLUNBNjEgVEVTVC1PTkxZMFkwEwYHKoZI
            zj0CAQYIKoZIzj0DAQcDQgAEfPaldrw1h2xuJgYgwZeG2PlqSGYInBUs7NEvujmv
            r3ueeFykeO+1F9sxgIH7JcuY+L4RJBHkoc5TuRR961Y39KOB+zCB+DAdBgNVHQ4E
            FgQUnzXgMKl/yvhmn5AKQs27gWWfSf4wHwYDVR0jBBgwFoAUsvAJPk0L4wgkgJY1
            bjo2MyvySxowSgYIKwYBBQUHAQEEPjA8MDoGCCsGAQUFBzABhi5odHRwOi8vb2Nz
            cC10ZXN0cmVmLnJvb3QtY2EudGktZGllbnN0ZS5kZS9vY3NwMA4GA1UdDwEB/wQE
            AwIBBjBGBgNVHSAEPzA9MDsGCCqCFABMBIEjMC8wLQYIKwYBBQUHAgEWIWh0dHA6
            Ly93d3cuZ2VtYXRpay5kZS9nby9wb2xpY2llczASBgNVHRMBAf8ECDAGAQH/AgEA
            MAoGCCqGSM49BAMCA0cAMEQCIFd7BzrFdsAitq3632W2SaWzxA4dJlfq1N4dQEDA
            yIs4AiBwWiFraxWRn2YFBj5ZvvZIGuIC2l62J0TgID4IzBDuyg==
          """
              .trimIndent()
      )

  val guardGoodDate = Date(1780402662000) // Jun 2  12:17:42 2026 GMT

  val guardGoodResponse: ByteArray =
      Base64.decode(
          """
            MIIEZwoBAKCCBGAwggRcBgkrBgEFBQcwAQEEggRNMIIESTCCAUihWDBWMQswCQYDVQQGEwJERTEa
            MBgGA1UECgwRZ2VtYXRpayBOT1QtVkFMSUQxKzApBgNVBAMMImVoY2EgT0NTUCBTaWduZXIgNjEg
            bmlzdCBURVNULU9OTFkYDzIwMjYwNjAyMTIwNTQwWjCBtjCBszBAMAkGBSsOAwIaBQAEFBfZqIJe
            HDzpYQwCKYYgXOSI+i7FBBSfNeAwqX/K+GafkApCzbuBZZ9J/gIHAtIwvM27B4AAGA8yMDI2MDYw
            MjEyMDU0MFqhXDBaMBoGBSskCAMMBBEYDzIwMjYwMjI2MDkzOTE2WjA8BgUrJAgDDQQzMDEwDQYJ
            YIZIAWUDBAIBBQAEINy22dv68w2PIlIRIL7wVpUoFsRK5DYjVuexj9oMAT9JoSIwIDAeBgkrBgEF
            BQcwAQYEERgPMTg3MDAxMDcwMDAwMDBaMAoGCCqGSM49BAMCA0cAMEQCICW5u8tJ2M0Sj6k55Tpj
            v8zbfIfxvSQaPD8j59qqLQXCAiBsHjQmltOa91RhGFDLQJhW8DCJtduj7kN9cJihcvw8EaCCAqQw
            ggKgMIICnDCCAkKgAwIBAgIHA5muRFWe+DAKBggqhkjOPQQDAjCBhDELMAkGA1UEBhMCREUxHzAd
            BgNVBAoMFmdlbWF0aWsgR21iSCBOT1QtVkFMSUQxMjAwBgNVBAsMKUtvbXBvbmVudGVuLUNBIGRl
            ciBUZWxlbWF0aWtpbmZyYXN0cnVrdHVyMSAwHgYDVQQDDBdHRU0uS09NUC1DQTYxIFRFU1QtT05M
            WTAeFw0yMzA4MDMwMDAwMDBaFw0yODA4MDMyMzU5NTlaMFYxCzAJBgNVBAYTAkRFMRowGAYDVQQK
            DBFnZW1hdGlrIE5PVC1WQUxJRDErMCkGA1UEAwwiZWhjYSBPQ1NQIFNpZ25lciA2MSBuaXN0IFRF
            U1QtT05MWTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGfevYAJf/RRsAiSFmKjHPLEq3oBu5Rf
            SyoMCy6Y4p4UPNCUO+YH4FoiIsdOsu7V4RI4N8HGOBVrFWW9F1N0utejgcswgcgwDAYDVR0TAQH/
            BAIwADATBgNVHSUEDDAKBggrBgEFBQcDCTAOBgNVHQ8BAf8EBAMCBkAwPAYIKwYBBQUHAQEEMDAu
            MCwGCCsGAQUFBzABhiBodHRwOi8vZWhjYS5nZW1hdGlrLmRlL25pc3Qtb2NzcDAVBgNVHSAEDjAM
            MAoGCCqCFABMBIEjMB8GA1UdIwQYMBaAFJ814DCpf8r4Zp+QCkLNu4Fln0n+MB0GA1UdDgQWBBQP
            UYNHFEKjdOVdq2FGl1UdIs3VHjAKBggqhkjOPQQDAgNIADBFAiEAo9ru46UMXgAJ5M+zIPToTv87
            60hHQoXEpmmBo6LqTEICIB//Y6XHfQTi0y2U44eVzJ0CI5IxeCA734KJ6JX/qOaE
          """
              .trimIndent()
      )

  private fun parseCertificate(encoded: String): X509Certificate {
    return CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(Base64.decode(encoded))) as X509Certificate
  }

  private class FakeHttp(statusCode: Int, content: ByteArray) :
    BasicHttpResponse(BasicStatusLine(HttpVersion.HTTP_1_1, statusCode, null)), CloseableHttpResponse {
    init {
      this.entity = ByteArrayEntity(content, ContentType.APPLICATION_OCTET_STREAM)
    }

    override fun close() {}
  }
}
