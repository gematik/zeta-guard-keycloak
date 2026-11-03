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

import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe

private val FEDERATION_MASTER_JSON = requireNotNull(
    FederationMasterConfigTest::class.java.getResource("/federation-master.json")
) { "Test resource federation-master.json not found on the classpath" }.path

class FederationMasterConfigTest : ZetaGuardFunSpec() {
  init {
    test("resolves the fedmasterUrl from the provisioned file") {
      val url = resolveFedmasterUrl(FEDERATION_MASTER_JSON)
      url shouldBe "http://gsi-fedmaster:8083"
    }

    test("returns null when the file does not exist") {
      val url = resolveFedmasterUrl("/nonexistent/path.json")
      url.shouldBeNull()
    }

    test("returns null when the file does not contain a JSON object") {
      val dir = java.nio.file.Files.createTempDirectory("fm-test")
      val file = dir.resolve("fm.json").toFile()
      file.writeText("""["not","an","object"]""")

      val url = resolveFedmasterUrl(file.absolutePath)
      url.shouldBeNull()

      dir.toFile().deleteRecursively()
    }

    test("returns null when fedmasterUrl field is missing") {
      val dir = java.nio.file.Files.createTempDirectory("fm-test")
      val file = dir.resolve("fm.json").toFile()
      file.writeText("""{"other": "value"}""")

      val url = resolveFedmasterUrl(file.absolutePath)
      url.shouldBeNull()

      dir.toFile().deleteRecursively()
    }

    test("trims trailing slash from the URL") {
      val dir = java.nio.file.Files.createTempDirectory("fm-test")
      val file = dir.resolve("fm.json").toFile()
      file.writeText("""{"fedmasterUrl":"http://fedmaster:8083/"}""")

      val url = resolveFedmasterUrl(file.absolutePath)
      url shouldBe "http://fedmaster:8083"

      dir.toFile().deleteRecursively()
    }
  }
}
