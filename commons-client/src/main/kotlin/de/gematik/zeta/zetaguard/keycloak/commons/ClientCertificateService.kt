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

import de.gematik.zeta.zetaguard.keycloak.commons.server.toCertificate
import de.gematik.zeta.zetaguard.keycloak.commons.server.toPrivateKey
import java.io.File
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.zip.ZipFile
import org.apache.commons.io.IOUtils

object ClientCertificateService {
  private val zipFile: ZipFile by lazy {
    val tempFile = File.createTempFile("certificates", ".zip").apply { deleteOnExit() }
    IOUtils.copy(ClientCertificateService::class.java.getResourceAsStream("/smcb-certificates-client.zip"), tempFile.outputStream())

    ZipFile(tempFile)
  }

  fun getPrivateKey(index: Int): PrivateKey {
    val suffix = index.toLeafSuffix()
    val entry = zipFile.getEntry("$CRT_GEMATIK_LEAF$suffix/private") ?: throw IllegalStateException("Key not found for index $index")

    return zipFile.getInputStream(entry).readBytes().toPrivateKey()
  }

  fun getCertificate(index: Int): X509Certificate {
    val suffix = index.toLeafSuffix()
    val entry = zipFile.getEntry("$CRT_GEMATIK_LEAF$suffix/certificate") ?: throw IllegalStateException("Certificate not found for index $index")

    return zipFile.getInputStream(entry).readBytes().toCertificate()
  }
}

fun Int.toLeafSuffix(): String = ".%05d".format(this)
