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
import de.gematik.zeta.zetaguard.keycloak.commons.server.SEKIDP_IDENTITY_PROVIDER_ID
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException
import java.security.KeyStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.apache.http.conn.ssl.NoopHostnameVerifier
import org.apache.http.impl.client.CloseableHttpClient
import org.apache.http.impl.client.HttpClients
import org.apache.http.ssl.SSLContexts
import org.keycloak.Config
import org.keycloak.broker.provider.IdentityProvider
import org.keycloak.common.enums.HostnameVerificationPolicy
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.provider.ProviderFactory
import org.keycloak.truststore.TruststoreProvider

private const val TEST_PASSWORD = "test-password"

class SekIdpHttpClientTest : ZetaGuardFunSpec() {
  init {
    test("a missing keystore file fails closed") {
      val config = MTLSClientConfig(keystoreLocation = "/does/not/exist.p12", keystorePassword = TEST_PASSWORD)

      shouldThrow<FileNotFoundException> { config.keystore }
    }

    test("an unreadable keystore file fails closed") {
      // Empty file: BouncyCastle rejects it as a PKCS12 store, so no client is built.
      val corruptFile = withContext(Dispatchers.IO) {
        File.createTempFile("sekidp-client-corrupt", ".p12")
      }.apply { deleteOnExit() }

      shouldThrow<IOException> { MTLSClientConfig(corruptFile.absolutePath, TEST_PASSWORD).keystore }
    }

    // PAR and token requests both run through doPost, so proving the certificate here covers both (A_23183).
    context("mTLS — client certificate at PAR and token requests (A_23183)") {
      test("presents the client certificate to a server that demands one") {
        withMTLSServer { server ->
          val httpClientFactory = mtlsHttpClientFactory(MTLSClientConfig(CLIENT_KEYSTORE, CLIENT_KEYSTORE_PASSWORD))
          val session = sessionTrusting(server.serverTrust)
          val client = SimpleHttp.create(httpClientFactory.create(session).httpClient)

          client.doPost(server.parUrl).param("client_id", "zeta-guard").asResponse().use { it.status shouldBe 201 }
        }
      }

      test("without mTLS config the handshake fails — the 201 above really hinges on the certificate") {
        withMTLSServer { server ->
          // This plain client trusts the server, so the only difference to the test above is the missing key material.
          httpClientWithoutClientCertificate(server.serverTrust).use { httpClient ->
            val client = SimpleHttp.create(httpClient)

            // SSLException extends IOException; TLS 1.3 surfaces the missing certificate only on the first read.
            shouldThrow<IOException> { client.doPost(server.parUrl).param("client_id", "zeta-guard").asResponse() }
          }
        }
      }
    }
  }
}

/** An HTTPS listener that answers `/par` with 201 — but only for clients presenting the committed test certificate. */
private class MTLSServer(val parUrl: String, val serverTrust: KeyStore)

/**
 * Runs [block] against a WireMock HTTPS listener requiring TLS client authentication.
 *
 * The server credential is generated per run and handed to the caller as a truststore; the accepted client
 * certificates are exactly the ones in [CLIENT_KEYSTORE], so the positive test also proves that generated keystore
 * is usable.
 */
private fun withMTLSServer(block: (MTLSServer) -> Unit) {
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
              .trustStorePassword(CLIENT_KEYSTORE_PASSWORD)
      )
          .apply { start() }

  try {
    server.stubFor(
        any(urlPathEqualTo("/par"))
            .willReturn(
                aResponse().withStatus(201).withHeader("Content-Type", "application/json").withBody("""{"request_uri":"urn:mock","expires_in":60}""")
            )
    )
    block(MTLSServer("https://127.0.0.1:${server.httpsPort()}/par", serverTrust))
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

/** The factory as Keycloak initializes it: `init`, then `postInit` reading the key material from the SekIDP factory. */
private fun mtlsHttpClientFactory(mtlsConfig: MTLSClientConfig): SekIDPHttpClientFactory {
  val sekIdpFactory = mockk<SekIDPIdentityProviderFactory>().also { every { it.mtlsConfig() } returns mtlsConfig }
  val sessionFactory =
      mockk<KeycloakSessionFactory>().also {
        @Suppress("UNCHECKED_CAST")
        every { it.getProviderFactory(IdentityProvider::class.java, SEKIDP_IDENTITY_PROVIDER_ID) } returns sekIdpFactory as ProviderFactory<IdentityProvider<*>>
      }

  return SekIDPHttpClientFactory().apply {
    init(Config.scope())
    postInit(sessionFactory)
  }
}

/** A session whose TruststoreProvider trusts [truststore] — what the mTLS client factory reads to build its SSLContext. */
private fun sessionTrusting(truststore: KeyStore): KeycloakSession =
    mockk<KeycloakSession>().also { session ->
      every { session.getProvider(TruststoreProvider::class.java) } returns
          mockk<TruststoreProvider>().also {
            every { it.policy } returns HostnameVerificationPolicy.ANY
            every { it.truststore } returns truststore
          }
    }
