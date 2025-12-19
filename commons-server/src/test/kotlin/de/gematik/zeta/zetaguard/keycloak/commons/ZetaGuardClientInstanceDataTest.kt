/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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

import com.fasterxml.jackson.databind.exc.InvalidTypeIdException
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.asMap
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.EncodingUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.AndroidZetaPlatformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.AppleZetaPlatformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.DISCRIMINATOR
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.LinuxZetaPlatformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.WindowsZetaPlatformProductId
import de.gematik.zeta.zetaguard.keycloak.commons.client_assertion.ZetaGuardClientInstanceData
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.maps.shouldContain
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

class ZetaGuardClientInstanceDataTest : FunSpec() {
  init {
    test("Serialize and deserialize polymorphic data") {
      val android = AndroidZetaPlatformProductId("package", listOf("fingerprint"))
      val apple = AppleZetaPlatformProductId("macos", listOf("bundle"))
      val linux = LinuxZetaPlatformProductId("packaging", "app-id")
      val windows = WindowsZetaPlatformProductId("store", "family")
      val platforms = mapOf("android" to android, "apple" to apple, "linux" to linux, "windows" to windows)

      platforms.forEach { platform ->
        val data = ZetaGuardClientInstanceData("name", "client", "jens-id", "jens", "info@jens.de", 4711L, platform.value)
        val json = data.toJSON()

        json shouldContain "\"name\":\"name\""
        json shouldContain "\"owner_mail\":\"info@jens.de\""
        json shouldContain "\"$DISCRIMINATOR\":\"${platform.key}\""
        json shouldNotContain "@type"

        val clientInstanceData = json.toObject<ZetaGuardClientInstanceData>()
        clientInstanceData shouldBe data
      }
    }

    test("Conversion from/to map") {
      val android = AndroidZetaPlatformProductId("package", listOf("fingerprint"))
      val data = ZetaGuardClientInstanceData("name", "client", "jens-id", "jens", "info@jens.de", 4711L, android)
      val asMap = data.asMap()

      asMap shouldContain ("owner_mail" to "info@jens.de")
      asMap shouldContain ("platform_product_id" to android.asMap())

      val platform = asMap["platform_product_id"] as Map<*, *>
      platform["@type"] shouldBe null
      platform[DISCRIMINATOR] shouldBe "android"

      asMap.toObject<ZetaGuardClientInstanceData>() shouldBe data
    }

    test("Broken platform") {
      val json =
          """
          {
            "name": "name",
            "client_id": "client",
            "manufacturer_id": "jens-id",
            "manufacturer_name": "jens",
            "owner_mail": "info@jens.de",
            "registration_timestamp": 4711,
            "platform_product_id": {
              "$DISCRIMINATOR": "jens"
            }
          }
          """
              .trimIndent()

      shouldThrow<InvalidTypeIdException> { json.toObject<ZetaGuardClientInstanceData>() }
    }
  }
}
