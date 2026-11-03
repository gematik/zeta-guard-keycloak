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
package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.CertificateGenerator
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import java.io.File
import java.security.KeyPair
import java.security.cert.X509Certificate
import org.keycloak.common.util.PemUtils

private const val TRUSTED_CA = "CN=Resource Server CA TEST-ONLY"
private const val FOREIGN_CA = "CN=Foreign CA TEST-ONLY"

/**
 * Throwaway PKI for the resource server accessing `userinfo/email`, generated per run: Keycloak trusts [trustedCa], which
 * issued [trustedResourceServer]; [foreignResourceServer] comes from a CA Keycloak does not know.
 */
object ResourceServerPki {
  /** Mounted into the Keycloak container by `docker-compose-it.yml`. */
  val truststoreFile = File("./target/resource-server-truststore-testonly.pem")

  private val trustedCaKeys = generateKeyPair()
  private val foreignCaKeys = generateKeyPair()

  private val trustedCa = CertificateGenerator(TRUSTED_CA, trustedCaKeys, TRUSTED_CA, trustedCaKeys, isCA = true, isRootCA = true).buildCertificate()

  val trustedResourceServer = leaf("CN=resource-server TEST-ONLY", TRUSTED_CA, trustedCaKeys)
  val foreignResourceServer = leaf("CN=foreign-resource-server TEST-ONLY", FOREIGN_CA, foreignCaKeys)

  fun writeTruststore() {
    truststoreFile.parentFile.mkdirs()
    truststoreFile.writeText(trustedCa.toPem())
  }

  private fun leaf(subject: String, issuer: String, issuerKeys: KeyPair): X509Certificate =
      CertificateGenerator(subject, generateKeyPair(), issuer, issuerKeys, isCA = false, createAdmissionExtension = false).buildCertificate()
}

fun X509Certificate.toPem(): String = "-----BEGIN CERTIFICATE-----\n${PemUtils.encodeCertificate(this)}\n-----END CERTIFICATE-----\n"
