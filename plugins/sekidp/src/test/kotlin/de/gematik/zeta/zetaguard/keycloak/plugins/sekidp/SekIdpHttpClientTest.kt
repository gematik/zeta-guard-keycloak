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
package de.gematik.zeta.zetaguard.keycloak.plugins.sekidp

import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock.aResponse
import com.github.tomakehurst.wiremock.client.WireMock.any
import com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo
import com.github.tomakehurst.wiremock.core.WireMockConfiguration.options
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import org.keycloak.common.enums.HostnameVerificationPolicy
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.KeycloakSession
import org.keycloak.truststore.TruststoreProvider

private const val TEST_PASSWORD = "test-password"

class SekIdpHttpClientTest : ZetaGuardFunSpec() {
  init {
    test("without mTLS config no keystore is read and no certificate is published") {
      SekIdpHttpClient(null).use { client -> client.clientCertificate shouldBe null }
    }

    test("a missing keystore file fails closed") {
      val config = MtlsClientConfig(keystoreLocation = "/does/not/exist.p12", keystorePassword = TEST_PASSWORD)

      shouldThrow<FileNotFoundException> { SekIdpHttpClient(config) }
    }

    test("an unreadable keystore file fails closed") {
      // Empty file: BouncyCastle rejects it as a PKCS12 store, so no client is built.
      val corruptFile = File.createTempFile("sekidp-client-corrupt", ".p12").apply { deleteOnExit() }

      shouldThrow<IOException> { SekIdpHttpClient(MtlsClientConfig(corruptFile.absolutePath, TEST_PASSWORD)) }
    }

    // PAR and token requests both run through doPost, so proving the certificate here covers both (A_23183).
    context("mTLS — client certificate at PAR and token requests (A_23183)") {
      test("presents the client certificate to a server that demands one") {
        withMtlsServer { server ->
          SekIdpHttpClient(MtlsClientConfig(CLIENT_KEYSTORE, CLIENT_KEYSTORE_PASSWORD)).use { client ->
            val session = sessionTrusting(server.serverTrust)

            client.doPost(session, server.parUrl).param("client_id", "zeta-guard").asResponse().use { it.status shouldBe 201 }
          }
        }
      }

      test("without mTLS config the handshake fails — the 201 above really hinges on the certificate") {
        withMtlsServer { server ->
          SekIdpHttpClient(null).use { client ->
            // This plain client trusts the server, so the only difference to the test above is the missing key material.
            httpClientWithoutClientCertificate(server.serverTrust).use { httpClient ->
              val session = sessionUsing(httpClient)

              // SSLException extends IOException; TLS 1.3 surfaces the missing certificate only on the first read.
              shouldThrow<IOException> { client.doPost(session, server.parUrl).param("client_id", "zeta-guard").asResponse() }
            }
          }
        }
      }
    }
  }
}

/** An HTTPS listener that answers `/par` with 201 — but only for clients presenting the committed test certificate. */
private class MtlsServer(val parUrl: String, val serverTrust: KeyStore)

/**
 * Runs [block] against a WireMock HTTPS listener requiring TLS client authentication.
 *
 * The server credential is generated per run and handed to the caller as a truststore; the accepted client
 * certificates are exactly the ones in [CLIENT_KEYSTORE], so the positive test also proves that generated keystore
 * is usable.
 */
private fun withMtlsServer(block: (MtlsServer) -> Unit) {
  val (serverKeystoreFile, serverCertificate) = generateSelfSignedKeystore("server", "127.0.0.1", TEST_PASSWORD)
  val serverTrust = KeyStore.getInstance("PKCS12").apply { load(null, null) }.apply { setCertificateEntry("server", serverCertificate) }

  val server =
      WireMockServer(
              options()
                  .dynamicPort()
                  .dynamicHttpsPort()
                  .bindAddress("127.0.0.1")
                  .keystorePath(serverKeystoreFile.absolutePath)
                  .keystoreType("PKCS12")
                  .keystorePassword(TEST_PASSWORD)
                  .keyManagerPassword(TEST_PASSWORD)
                  .needClientAuth(true)
                  .trustStorePath(CLIENT_KEYSTORE)
                  .trustStoreType("PKCS12")
                  .trustStorePassword(CLIENT_KEYSTORE_PASSWORD))
          .apply { start() }

  try {
    server.stubFor(
        any(urlPathEqualTo("/par"))
            .willReturn(aResponse().withStatus(201).withHeader("Content-Type", "application/json").withBody("""{"request_uri":"urn:mock","expires_in":60}""")))
    block(MtlsServer("https://127.0.0.1:${server.httpsPort()}/par", serverTrust))
  } finally {
    server.stop()
  }
}

/** An Apache client that trusts the test server but holds no key material to present. */
private fun httpClientWithoutClientCertificate(serverTrust: KeyStore): CloseableHttpClient =
    HttpClients.custom()
        .setSSLContext(SSLContexts.custom().loadTrustMaterial(serverTrust, null).build())
        .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
        .build()

/** A session whose TruststoreProvider trusts [truststore] — what the mTLS client factory reads to build its SSLContext. */
private fun sessionTrusting(truststore: KeyStore): KeycloakSession =
    mockk<KeycloakSession>().also { session ->
      every { session.getProvider(TruststoreProvider::class.java) } returns
          mockk<TruststoreProvider>().also {
            every { it.policy } returns HostnameVerificationPolicy.ANY
            every { it.truststore } returns truststore
          }
    }

/** A session whose HttpClientProvider hands back [httpClient] — what the non-mTLS path falls back to. */
private fun sessionUsing(httpClient: CloseableHttpClient): KeycloakSession =
    mockk<KeycloakSession>().also { session ->
      every { session.getProvider(HttpClientProvider::class.java) } returns
          mockk<HttpClientProvider>().also {
            every { it.httpClient } returns httpClient
            every { it.maxConsumedResponseSize } returns HttpClientProvider.DEFAULT_MAX_CONSUMED_RESPONSE_SIZE
          }
    }
