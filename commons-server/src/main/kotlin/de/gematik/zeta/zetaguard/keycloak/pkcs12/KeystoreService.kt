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
package de.gematik.zeta.zetaguard.keycloak.pkcs12

import java.io.InputStream
import java.security.KeyStore
import java.security.PrivateKey
import java.security.cert.X509Certificate
import javax.security.auth.x500.X500Principal
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12

open class KeystoreService(stream: InputStream, password: String) {
  private val keystore: KeyStore by lazy {
    KeyStore.getInstance(PKCS12.name, PROVIDER_NAME) // Always use BC in order to handle Brainpool curve
        .apply { load(stream, password.toCharArray()) }
  }
  private val certificates: Map<String, X509Certificate> by lazy {
    val aliases = keystore.aliases().toList().map { it.uppercase() }.toSet()

    aliases.associateWith { getCertificate(it) }
  }

  private val certificatesBySubject: Map<X500Principal, X509Certificate> by lazy { certificates.values.associateBy { it.subjectX500Principal } }

  protected val aliasBySubject: Map<X500Principal, String> by lazy { certificates.map { it.value.subjectX500Principal to it.key }.toMap() }

  fun aliases() = certificates.keys

  fun hasCertificate(name: String): Boolean = aliases().contains(name.uppercase())

  fun hasCertificate(certificate: X509Certificate): Boolean = aliasBySubject[certificate.subjectX500Principal] != null

  fun getPrivateKey(name: String, password: String): PrivateKey {
    val key = keystore.getKey(name.uppercase(), password.toCharArray()) ?: keystore.getCertificate(name)

    requireNotNull(key) { "Key »$name« not found." }

    return key as PrivateKey
  }

  fun findCertificate(name: String): X509Certificate? = certificates[name.uppercase()]

  fun findIssuerCertificate(certificate: X509Certificate): X509Certificate? = certificatesBySubject[certificate.issuerX500Principal]

  private fun getCertificate(name: String): X509Certificate {
    val certificate = keystore.getCertificate(name.uppercase()) ?: keystore.getCertificate(name)

    requireNotNull(certificate) { "Certificate »$name« not found." }

    return certificate as X509Certificate
  }
}
