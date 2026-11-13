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
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12

/**
 * Key material for the mTLS client of the SekIDP endpoints that demand client authentication — PAR and token
 * (self_signed_tls_client_auth, A_23183). The HTTP client itself is provided by [SekIDPHttpClientFactory]; the client
 * certificate is also published in the Guard's entity statement, so both always come from the same keystore.
 *
 * The keystore is read once on first use; no config at all means no mTLS.
 */
data class MTLSClientConfig(
    val keystoreLocation: String,
    val keystorePassword: String,
) {
  val keystore: KeyStore by lazy { loadKeystore() }
  val clientCertificate: X509Certificate by lazy { singleClientCertificate() }

  private fun singleClientCertificate(): X509Certificate {
    val aliases = keystore.aliases().toList()
    val alias = requireNotNull(aliases.singleOrNull()) { "mTLS keystore must hold exactly one entry, found ${aliases.size} ${aliases.sorted()}" }

    return requireNotNull(keystore.getCertificate(alias) as? X509Certificate) { "mTLS keystore has no certificate for alias »$alias«" }
  }

  private fun loadKeystore(): KeyStore = KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply {
    File(keystoreLocation).inputStream().use { load(it, keystorePassword.toCharArray()) }
  }
}
