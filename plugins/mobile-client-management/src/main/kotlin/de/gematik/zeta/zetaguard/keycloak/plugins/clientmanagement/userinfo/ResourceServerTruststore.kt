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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.userinfo

import java.io.File
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.Config

/** Truststore dedicated to resource servers calling `userinfo/email`; env `KC_SPI_REALM_RESTAPI_EXTENSION__ZETA__RESOURCE_SERVER_TRUSTSTORE_FILE`. */
const val CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE = "resourceServerTruststoreFile"
const val CONFIG_RESOURCE_SERVER_TRUSTSTORE_PASSWORD = "resourceServerTruststorePassword"

/** Keycloak's own mTLS truststore (`KC_HTTPS_TRUST_STORE_FILE`), used when no dedicated truststore is configured. */
const val KC_HTTPS_TRUST_STORE_FILE = "https-trust-store-file"
const val KC_HTTPS_TRUST_STORE_PASSWORD = "https-trust-store-password"

data class TruststoreLocation(val file: String, val password: String?, val option: String)

/**
 * Trust anchors for authenticating resource servers via mTLS. Never shared with Keycloak's outbound truststore (`conf/truststores`), which also
 * contains the public JDK CAs.
 */
object ResourceServerTruststore {

  /** The dedicated truststore if configured, otherwise Keycloak's HTTPS truststore, otherwise none. */
  fun resolveLocation(config: Config.Scope): TruststoreLocation? {
    config[CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE]
        ?.takeIf { it.isNotBlank() }
        ?.let {
          return TruststoreLocation(it, config[CONFIG_RESOURCE_SERVER_TRUSTSTORE_PASSWORD], CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE)
        }

    val root = config.root()

    return root[KC_HTTPS_TRUST_STORE_FILE]
        ?.takeIf { it.isNotBlank() }
        ?.let { TruststoreLocation(it, root[KC_HTTPS_TRUST_STORE_PASSWORD], KC_HTTPS_TRUST_STORE_FILE) }
  }

  /** All certificates of a PKCS12 (`.p12`, `.pfx`), JKS (`.jks`) or PEM bundle (anything else). Fails if there are none. */
  fun load(location: TruststoreLocation): Set<X509Certificate> {
    val file = File(location.file)
    val certificates =
        when (file.extension.lowercase()) {
          "p12",
          "pfx" -> keystoreCertificates(KeyStore.getInstance("PKCS12", PROVIDER_NAME), file, location.password)
          "jks" -> keystoreCertificates(KeyStore.getInstance("JKS"), file, location.password)
          else -> pemCertificates(file)
        }

    check(certificates.isNotEmpty()) { "Resource server truststore »${location.file}« (${location.option}) contains no certificates" }

    return certificates
  }

  private fun keystoreCertificates(keystore: KeyStore, file: File, password: String?): Set<X509Certificate> {
    file.inputStream().use { keystore.load(it, password?.toCharArray()) }

    return keystore.aliases().toList().mapNotNull { keystore.getCertificate(it) as? X509Certificate }.toSet()
  }

  private fun pemCertificates(file: File): Set<X509Certificate> =
      file.inputStream().use {
        CertificateFactory.getInstance("X.509", PROVIDER_NAME).generateCertificates(it).filterIsInstance<X509Certificate>().toSet()
      }
}
