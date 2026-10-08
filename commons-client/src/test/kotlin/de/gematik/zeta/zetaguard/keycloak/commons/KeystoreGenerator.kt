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

const val SMCB_KEYSTORE_PASSWORD = "tyqvHpFoHdu68yRE+0F4q/I"

fun main(@Suppress("unused") args: Array<String>) {
  setupSecurityProviders()
  CryptoIntegration.init(CertificateChain::class.java.getClassLoader())

  val serverKeyStore = KeyStore.getInstance(PKCS12.name, PROVIDER_NAME).apply { load(null) }
  val clientCertificatesFile = FileOutputStream("smcb-certificates-client.zip")
  val clientCertificates = ZipOutputStream(clientCertificatesFile)
  val certificateChain = CertificateChain()
  val password = SMCB_KEYSTORE_PASSWORD.toCharArray()

  with(certificateChain) {
    logger.info("Generating certificate: $leafCertName")
    serverKeyStore.setCertificateEntry(CRT_GEMATIK_ROOT, rootCert)
    serverKeyStore.setCertificateEntry(CRT_GEMATIK_INTERMEDIATE, intermediateCert)
    serverKeyStore.setCertificateEntry(leafCertName, leafCert)
    serverKeyStore.setKeyEntry(leafCertName, leafKeyPair.private, password, arrayOf(leafCert, intermediateCert, rootCert))

    storeLeafCertificate(clientCertificates)
  }

  serverKeyStore.store(File("smcb-certificates-server.p12").outputStream(), password)

  for (i in 1..5000) {
    val certificateChain = certificateChain.createLeafCertificate(i)

    with(certificateChain) {
      logger.info("Generating certificate: $leafCertName")

      storeLeafCertificate(clientCertificates)
    }
  }

  clientCertificates.close()
}

private fun CertificateChain.storeLeafCertificate(clientCertificates: ZipOutputStream) {
  val privateKeyEntry = ZipEntry("$leafCertName/private")
  clientCertificates.putNextEntry(privateKeyEntry)
  clientCertificates.write(leafKeyPair.private.encoded)
  clientCertificates.closeEntry()

  val leafCertificateEntry = ZipEntry("$leafCertName/certificate")
  clientCertificates.putNextEntry(leafCertificateEntry)
  clientCertificates.write(leafCert.encoded)
  clientCertificates.closeEntry()
}
