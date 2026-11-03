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

import de.gematik.zeta.zetaguard.keycloak.commons.server.EC_CURVE_P256
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import java.io.File
import java.io.FileOutputStream
import java.security.KeyStore
import java.util.zip.ZipEntry
import java.util.zip.ZipOutputStream
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.common.util.KeystoreUtil.KeystoreFormat.PKCS12


/**
 * Helper class to generate a PKCS12 truststore (server-side) and a ZIP (client-side) with derived certificates for testing purposes.
 *
 * Opposite to production truststores, the store contain the private keys of the certificates for signing data, etc.
 */
class KeystoreGenerator(private val certificateChain: CertificateChain, private val fileName: String, password: String) : AutoCloseable {
  private val serverKeyStore = KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply { load(null) }
  private val clientCertificatesFile = FileOutputStream("$fileName-client.zip")
  private val clientCertificates = ZipOutputStream(clientCertificatesFile)
  private val password = password.toCharArray()

  fun createServerTruststore() {
    with(certificateChain) {
      serverKeyStore.setCertificateEntry(config.rootCertName, rootCert)
      serverKeyStore.setCertificateEntry(config.intermediateCertName, intermediateCert)
      serverKeyStore.setCertificateEntry(leafCertificate.leafCertName, leafCertificate.leafCert)
      serverKeyStore.setKeyEntry(
          config.rootCertName, rootKeyPair.private, password, arrayOf(rootCert)
      )
      serverKeyStore.setKeyEntry(
          config.intermediateCertName, intermediateKeyPair.private, password, arrayOf(intermediateCert, rootCert)
      )
      serverKeyStore.setKeyEntry(
          leafCertificate.leafCertName, leafCertificate.leafKeyPair.private, password, arrayOf(leafCertificate.leafCert, intermediateCert, rootCert)
      )
    }
  }

  fun createClientZIP(leafCertificates: Int) {
    logger.info("Store client certificate: ${certificateChain.leafCertificate.leafCertName}")
    certificateChain.leafCertificate.storeLeafCertificate(clientCertificates)

    for (i in 1..leafCertificates) {
      val leafCertificate = certificateChain.createLeafCertificate(i)

      with(leafCertificate) {
        logger.info("Store client certificate: $leafCertName")

        storeLeafCertificate(clientCertificates)
      }
    }
  }

  override fun close() {
    val file = File("$fileName-server.p12")

    logger.info("Writing server certificate: ${file.absolutePath}")
    serverKeyStore.store(file.outputStream(), password)
    clientCertificates.close()
  }

  companion object {
    init {
      setupSecurityProviders()
      CryptoIntegration.init(CertificateChain::class.java.getClassLoader())
    }
  }
}

private fun CertificateChain.LeafCertificate.storeLeafCertificate(clientCertificates: ZipOutputStream) {
  val privateKeyEntry = ZipEntry("$leafCertName/private")
  clientCertificates.putNextEntry(privateKeyEntry)
  clientCertificates.write(leafKeyPair.private.encoded)
  clientCertificates.closeEntry()

  // Redundant, since derivable from certificate
  val publicKeyEntry = ZipEntry("$leafCertName/public")
  clientCertificates.putNextEntry(publicKeyEntry)
  clientCertificates.write(leafKeyPair.public.encoded)
  clientCertificates.closeEntry()

  val leafCertificateEntry = ZipEntry("$leafCertName/certificate")
  clientCertificates.putNextEntry(leafCertificateEntry)
  clientCertificates.write(leafCert.encoded)
  clientCertificates.closeEntry()
}

object GoogleKeystoreGenerator {
  @JvmStatic
  fun main(@Suppress("unused") args: Array<String>) {
    val certificateChainConfiguration = CertificateChainConfiguration(
        EC_CURVE_P256,
        GOOGLE_ROOT_DN,
        GOOGLE_ROOT_CA,
        GOOGLE_INTERMEDIATE_DN,
        GOOGLE_INTERMEDIATE_CA,
        GOOGLE_LEAF_DN,
        GOOGLE_LEAF_CA,
        false
    )
    val keystoreGenerator = KeystoreGenerator(CertificateChain(certificateChainConfiguration), "google-certificates", GOOGLE_TRUSTSTORE_PASSWORD)

    keystoreGenerator.use {
      it.createServerTruststore()
      it.createClientZIP(0)
    }
  }
}

object AppleKeystoreGenerator {
  @JvmStatic
  fun main(@Suppress("unused") args: Array<String>) {
    val certificateChainConfiguration = CertificateChainConfiguration(
        EC_CURVE_P256,
        APPLE_ROOT_DN,
        APPLE_ROOT_CA,
        APPLE_INTERMEDIATE_DN,
        APPLE_INTERMEDIATE_CA,
        APPLE_LEAF_DN,
        APPLE_LEAF_CA,
        false
    )
    val keystoreGenerator = KeystoreGenerator(CertificateChain(certificateChainConfiguration), "apple-certificates", APPLE_TRUSTSTORE_PASSWORD)

    keystoreGenerator.use {
      it.createServerTruststore()
      it.createClientZIP(0)
    }
  }
}
