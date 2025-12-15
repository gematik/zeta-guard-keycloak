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
package de.gematik.zeta.zetaguard.keycloak.pkcs12

import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12

class KeystoreService(stream: InputStream, password: String) {
  private val keystore: KeyStore by lazy {
    KeyStore.getInstance(PKCS12.name, PROVIDER_NAME) // Always use BC in order to handle Brainpool curve
        .apply { load(stream, password.toCharArray()) }
  }
  private val aliases: List<String> by lazy { keystore.aliases().toList().map { it.uppercase() } }

  fun aliases() = aliases

  fun hasCertificate(name: String): Boolean = aliases().contains(name.uppercase())

  fun getCertificate(name: String): X509Certificate {
    val certificate = keystore.getCertificate(name.uppercase()) ?: keystore.getCertificate(name)

    if (certificate == null) {
      throw IllegalArgumentException("Certificate »$name« not found.")
    }

    return certificate as X509Certificate
  }

  fun getPrivateKey(name: String, password: String): PrivateKey {
    val key = keystore.getKey(name.uppercase(), password.toCharArray()) ?: keystore.getCertificate(name)

    if (key == null) {
      throw IllegalArgumentException("Key »$name« not found.")
    }

    return key as PrivateKey
  }

  fun certificates() = aliases().map { getCertificate(it) }

  fun findIssuerCertificate(certificate: X509Certificate) = certificates().firstOrNull { it.subjectX500Principal == certificate.issuerX500Principal }
}
