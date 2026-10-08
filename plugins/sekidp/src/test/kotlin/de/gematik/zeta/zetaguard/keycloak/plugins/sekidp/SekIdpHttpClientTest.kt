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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.File
import java.io.FileNotFoundException
import java.io.IOException

private const val TEST_PASSWORD = "test-password"

class SekIdpHttpClientTest : FunSpec() {
  init {
    registerBouncyCastle()

    test("without mTLS config no keystore is read and no certificate is published") {
      SekIdpHttpClient(null).use { client -> client.clientCertificate shouldBe null }
    }

    test("a missing keystore file fails closed") {
      val config = MtlsClientConfig(keystoreLocation = "/does/not/exist.p12", keystorePassword = TEST_PASSWORD)

      shouldThrow<FileNotFoundException> { SekIdpHttpClient(config) }
    }

    test("an unreadable keystore file fails closed") {
      // Empty file: BouncyCastle rejects it as a PKCS12 store, so no client is built.
      val corruptFile = File.createTempFile("sekidp-client-corrupt", ".p12").apply { deleteOnExit() }

      shouldThrow<IOException> { SekIdpHttpClient(MtlsClientConfig(corruptFile.absolutePath, TEST_PASSWORD)) }
    }
  }
}
