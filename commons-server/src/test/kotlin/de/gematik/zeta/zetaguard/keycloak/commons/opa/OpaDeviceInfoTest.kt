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
package de.gematik.zeta.zetaguard.keycloak.commons.opa

import de.gematik.zeta.zetaguard.keycloak.client_assertion.AndroidPosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.AndroidProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleAssertionAuthenticatorData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleAttestationStatement
import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleAuthData
import de.gematik.zeta.zetaguard.keycloak.client_assertion.ApplePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.AppleProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.BiometricManager
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Build
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Crypto
import de.gematik.zeta.zetaguard.keycloak.client_assertion.DevicePolicyManager
import de.gematik.zeta.zetaguard.keycloak.client_assertion.KeyguardManager
import de.gematik.zeta.zetaguard.keycloak.client_assertion.LinuxProductId
import de.gematik.zeta.zetaguard.keycloak.client_assertion.PackageManager
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Product
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Ro
import de.gematik.zeta.zetaguard.keycloak.client_assertion.SoftwarePosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.TPMPosture
import de.gematik.zeta.zetaguard.keycloak.client_assertion.Version
import de.gematik.zeta.zetaguard.keycloak.client_assertion.WindowsProductId
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import io.kotest.matchers.shouldBe

class OpaDeviceInfoTest : ZetaGuardFunSpec() {
  init {
    test("software posture -> os and os_version, no device_model") {
      val posture = SoftwarePosture(LinuxProductId("packaging", "app-id"), "demo_client", "0.2.0", "Linux", "6.12.54-linuxkit", "aarch64", "key", "challenge")

      posture.toOpaDeviceInfo() shouldBe OpaDeviceInfo(os = "Linux", osVersion = "6.12.54-linuxkit", deviceModel = null)
    }

    test("tpm posture -> os and os_version, no device_model") {
      val posture =
          TPMPosture(WindowsProductId("store", "family"), "demo_client", "0.2.0", "Windows", "XP", "i686", "key", "quote", "signature", "log", listOf("cert1"))

      posture.toOpaDeviceInfo() shouldBe OpaDeviceInfo(os = "Windows", osVersion = "XP", deviceModel = null)
    }

    test("apple posture -> system name, system version and device model") {
      val posture =
          ApplePosture(
              AppleProductId("macos", listOf("bundle")),
              "demo_client",
              "0.2.0",
              "26.2",
              "macOS",
              "Apple M1 Max",
              "key-id",
              "format1",
              AppleAttestationStatement(listOf("cert1"), "receipt"),
              AppleAuthData("hash", "flags", 12L, "aaguid", "credo"),
              "signing",
              AppleAssertionAuthenticatorData("hash", 42L),
              "{}",
          )

      posture.toOpaDeviceInfo() shouldBe OpaDeviceInfo(os = "macOS", osVersion = "26.2", deviceModel = "Apple M1 Max")
    }

    test("android posture -> interim mapping with sdk version and build model") {
      val posture =
          AndroidPosture(
              AndroidProductId("package", listOf("digest")),
              "demo_client",
              "0.2.0",
              Build(Version(42L, "security"), "Samsung", "product", "Galaxy", "blackboard"),
              Ro(Crypto(true), Product(56L)),
              PackageManager(true, "28"),
              KeyguardManager(true),
              BiometricManager(true, biometricStrong = false),
              DevicePolicyManager(4),
              listOf("cert1"),
          )

      posture.toOpaDeviceInfo() shouldBe OpaDeviceInfo(os = "Android", osVersion = "42", deviceModel = "Galaxy")
    }
  }
}
