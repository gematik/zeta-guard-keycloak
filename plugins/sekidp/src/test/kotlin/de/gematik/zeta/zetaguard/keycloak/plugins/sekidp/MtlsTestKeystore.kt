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

import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import java.io.File
import java.security.KeyStore
import java.security.cert.Certificate
import org.keycloak.common.util.CertificateUtils

const val CLIENT_KEYSTORE_PASSWORD = "testpass123"

/**
 * A throwaway EC/P-256 client credential, CN=sekidp-mtls-test-client. In production this keystore is
 * operator-supplied. Shared by [SekIdpHttpClientTest] and [SekIDPIdentityProviderFactoryTest].
 */
val CLIENT_KEYSTORE: String by lazy {
  generateSelfSignedKeystore("sekidp-client", "sekidp-mtls-test-client", CLIENT_KEYSTORE_PASSWORD).file.absolutePath
}

data class GeneratedKeystore(val file: File, val certificate: Certificate)

/** A temp PKCS12 keystore holding a fresh self-signed EC/P-256 credential, CN=[commonName]. */
fun generateSelfSignedKeystore(alias: String, commonName: String, password: String): GeneratedKeystore {
  val keyPair = generateKeyPair()
  val certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, commonName)
  val file =
      File.createTempFile(alias, ".p12").apply {
        deleteOnExit()
        val keystore = KeyStore.getInstance("PKCS12").apply { load(null, null) }
        keystore.setKeyEntry(alias, keyPair.private, password.toCharArray(), arrayOf(certificate))
        outputStream().use { keystore.store(it, password.toCharArray()) }
      }
  return GeneratedKeystore(file, certificate)
}
