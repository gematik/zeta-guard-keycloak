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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.StringSpec
import io.kotest.engine.spec.tempdir
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.mockk.every
import io.mockk.mockk
import java.io.File
import java.security.KeyStore
import java.security.cert.X509Certificate
import java.util.Base64
import org.bouncycastle.jce.provider.BouncyCastleProvider.PROVIDER_NAME
import org.keycloak.Config

private const val PASSWORD = "changeit"

private fun scope(values: Map<String, String?>, root: Config.Scope? = null): Config.Scope {
  val scope = mockk<Config.Scope>()
  every { scope.get(any<String>()) } answers { values[firstArg()] }
  root?.let { every { scope.root() } returns it }
  return scope
}

private fun X509Certificate.pem() =
    "-----BEGIN CERTIFICATE-----\n${Base64.getMimeEncoder(64, "\n".toByteArray()).encodeToString(encoded)}\n-----END CERTIFICATE-----\n"

private fun File.writeKeystore(keystore: KeyStore, vararg certificates: X509Certificate) = apply {
  keystore.load(null, null)
  certificates.forEachIndexed { index, certificate -> keystore.setCertificateEntry("ca-$index", certificate) }
  outputStream().use { keystore.store(it, PASSWORD.toCharArray()) }
}

class ResourceServerTruststoreTest :
    StringSpec({
      val first = TestCa("First CA").certificate
      val second = TestCa("Second CA").certificate

      "the dedicated truststore wins over Keycloak's HTTPS truststore" {
        val root = scope(mapOf(KC_HTTPS_TRUST_STORE_FILE to "/https.p12", KC_HTTPS_TRUST_STORE_PASSWORD to "https-pw"))
        val config = scope(mapOf(CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE to "/rs.pem", CONFIG_RESOURCE_SERVER_TRUSTSTORE_PASSWORD to null), root)

        ResourceServerTruststore.resolveLocation(config) shouldBe TruststoreLocation("/rs.pem", null, CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE)
      }

      "without a dedicated truststore Keycloak's HTTPS truststore is used" {
        val root = scope(mapOf(KC_HTTPS_TRUST_STORE_FILE to "/https.p12", KC_HTTPS_TRUST_STORE_PASSWORD to "https-pw"))
        val config = scope(mapOf(CONFIG_RESOURCE_SERVER_TRUSTSTORE_FILE to " "), root)

        ResourceServerTruststore.resolveLocation(config) shouldBe TruststoreLocation("/https.p12", "https-pw", KC_HTTPS_TRUST_STORE_FILE)
      }

      "without any truststore there is no location" { ResourceServerTruststore.resolveLocation(scope(emptyMap(), scope(emptyMap()))) shouldBe null }

      "a PEM bundle yields all its certificates" {
        val file = File(tempdir(), "rs.pem").apply { writeText(first.pem() + second.pem()) }

        ResourceServerTruststore.load(TruststoreLocation(file.path, null, "test")) shouldBe setOf(first, second)
      }

      "a PKCS12 truststore yields all its certificates" {
        val file = File(tempdir(), "rs.p12").writeKeystore(KeyStore.getInstance("PKCS12", PROVIDER_NAME), first, second)

        ResourceServerTruststore.load(TruststoreLocation(file.path, PASSWORD, "test")) shouldBe setOf(first, second)
      }

      "a JKS truststore yields all its certificates" {
        val file = File(tempdir(), "rs.jks").writeKeystore(KeyStore.getInstance("JKS"), first)

        ResourceServerTruststore.load(TruststoreLocation(file.path, PASSWORD, "test")) shouldBe setOf(first)
      }

      "a truststore without certificates fails" {
        val file = File(tempdir(), "empty.pem").apply { writeText("") }

        shouldThrow<IllegalStateException> { ResourceServerTruststore.load(TruststoreLocation(file.path, null, "test")) }.message shouldContain
            "contains no certificates"
      }

      "a missing truststore file fails" {
        shouldThrow<Exception> { ResourceServerTruststore.load(TruststoreLocation("/does/not/exist.pem", null, "test")) }
      }
    })
