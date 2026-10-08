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

import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.Config
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12
import org.keycloak.connections.httpclient.DefaultHttpClientFactory
import org.keycloak.connections.httpclient.HttpClientBuilder
import org.keycloak.connections.httpclient.HttpClientSpi
import org.keycloak.http.simple.SimpleHttp
import org.keycloak.http.simple.SimpleHttpRequest
import org.keycloak.models.KeycloakSession

/**
 * Outbound HTTP client for the SekIDP endpoints that demand client authentication — PAR and token
 * (self_signed_tls_client_auth, A_23183). Bundles the mTLS-capable connection pool with the client
 * certificate that is published in the Guard's entity statement, so both always come from the same
 * keystore. Discovery/JWKS GETs deliberately stay on Keycloak's default HTTP client.
 *
 * The mTLS client is built on [DefaultHttpClientFactory], so it shares the default client's full
 * connections-http-client SPI configuration — truststore and hostname verification, proxy mappings,
 * timeouts, pool sizing — and differs only in the key material it presents. With mTLS disabled,
 * requests go through Keycloak's default HTTP client directly.
 */
class SekIdpHttpClient(config: MtlsClientConfig?) : AutoCloseable {

  /** Published in the Guard's entity statement so the SekIDP can match the presented certificate. Null when mTLS is disabled. */
  internal val clientCertificate: X509Certificate?

  private val mtlsClientFactory: DefaultHttpClientFactory?

  init {
    val keystore = config?.let { loadKeystore(it) }
    clientCertificate = keystore?.let { singleClientCertificate(it) }
    mtlsClientFactory = keystore?.let { mtlsClientFactory(it, config.keystorePassword) }
  }

  fun doPost(session: KeycloakSession, url: String): SimpleHttpRequest =
      (mtlsClientFactory?.let { SimpleHttp.create(it.create(session).httpClient) } ?: SimpleHttp.create(session)).doPost(url)

  override fun close() {
    mtlsClientFactory?.close()
  }

  private fun loadKeystore(config: MtlsClientConfig): KeyStore =
      KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply {
        File(config.keystoreLocation).inputStream().use { load(it, config.keystorePassword.toCharArray()) }
      }

  private fun singleClientCertificate(keystore: KeyStore): X509Certificate {
    val aliases = keystore.aliases().toList()
    val alias = requireNotNull(aliases.singleOrNull()) { "mTLS keystore must hold exactly one entry, found ${aliases.size} ${aliases.sorted()}" }
    return requireNotNull(keystore.getCertificate(alias) as? X509Certificate) { "mTLS keystore has no certificate for alias »$alias«" }
  }

  /** A second [DefaultHttpClientFactory] client: same SPI config as the default client, plus the SekIDP key material. */
  private fun mtlsClientFactory(keystore: KeyStore, keystorePassword: String): DefaultHttpClientFactory =
      object : DefaultHttpClientFactory() {
            override fun newHttpClientBuilder(session: KeycloakSession): HttpClientBuilder = HttpClientBuilder().keyStore(keystore, keystorePassword)
          }
          .apply { init(Config.scope(HttpClientSpi().name, "default")) }
}

/** The client keystore for mTLS. Read once when the client is built; no config at all means no mTLS. */
data class MtlsClientConfig(
    val keystoreLocation: String,
    val keystorePassword: String,
)
