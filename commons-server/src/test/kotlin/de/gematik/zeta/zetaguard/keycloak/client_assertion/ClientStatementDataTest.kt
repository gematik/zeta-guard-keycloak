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
package de.gematik.zeta.zetaguard.keycloak.client_assertion

import de.gematik.zeta.zetaguard.keycloak.client_attestation.calculateAttestationChallenge
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.ZetaGuardFunSpec
import de.gematik.zeta.zetaguard.keycloak.commons.server.generateKeyPair
import de.gematik.zeta.zetaguard.keycloak.commons.server.generatePKIData
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.string.shouldNotContain

class ClientStatementDataTest : ZetaGuardFunSpec() {
  init {
    test("Serialize and deserialize Android posture") {
      val android = AndroidProductId("package", listOf("8214b94cd8c44024e7f65a8bbf221b51f617fa4818a30761c596aa5e34dc3359"))
      val androidPosture1 =
          AndroidPosture(
              android,
              "demo_client",
              "0.2.0",
              Build(Version(42L, "security"), "Samsung", "product", "Galaxy", "blackboard"),
              Ro(Crypto(true), Product(56L)),
              PackageManager(true, "28"),
              KeyguardManager(true),
              BiometricManager(true, biometricStrong = false),
              DevicePolicyManager(4),
              listOf("cert1", "cert2"),
          )
      val data = ClientStatementData("jens", Platform.ANDROID, PostureType.ANDROID, androidPosture1, 4711L)
      val json = data.toJSON()

      json shouldContain "\"sub\":\"jens\""
      json shouldContain "\"platform\":\"android\""
      json shouldContain "\"posture_type\":\"android\""
      json shouldNotContain "@type"

      val clientInstanceData = json.toObject<ClientStatementData>()
      clientInstanceData shouldBe data
      val androidPosture2 = clientInstanceData.posture as AndroidPosture

      androidPosture2.biometricManager shouldBe androidPosture1.biometricManager
      androidPosture2.packageManager shouldBe androidPosture1.packageManager
      androidPosture2.keyguardManager shouldBe androidPosture1.keyguardManager
      androidPosture2.devicePolicyManager shouldBe androidPosture1.devicePolicyManager
      androidPosture2.keyAttestationCertificateChain shouldBe androidPosture1.keyAttestationCertificateChain
      androidPosture2.ro shouldBe androidPosture1.ro
      androidPosture2.build shouldBe androidPosture1.build
    }

    test("Serialize and deserialize Apple posture") {
      val apple = AppleProductId("macos", listOf("bundle"))
      val applePosture1 =
          ApplePosture(
              apple,
              "demo_client",
              "0.2.0",
              "GV25GC21",
              "macOS Tahoe 26.2",
              "Apple M1 Max",
              "2E9FF59D-2F25-4C70-BBD0-268CBB5678A6",
              "format1",
              AppleAttestationStatement(listOf("cert1", "cert2"), "receipt"),
              AppleAuthData(
                  "8214b94cd8c44024e7f65a8bbf221b51f617fa4818a30761c596aa5e34dc3359",
                  "-X --intercept",
                  12L,
                  "2E9FF59D-2F25-4C70-BBD0-268CBB5678A7",
                  "credo",
              ),
              "signing",
              AppleAssertionAuthenticatorData("8214b94cd8c44024e7f65a8bbf221b51f617fa4818a30761c596aa5e34dc3359", 42L),
              """{  "sub": "jens" }""",
          )
      val data = ClientStatementData("jens", Platform.APPLE, PostureType.APPLE, applePosture1, 4711L)
      val json = data.toJSON()

      json shouldContain "\"sub\":\"jens\""
      json shouldContain "\"platform\":\"apple\""
      json shouldContain "\"posture_type\":\"apple\""
      json shouldNotContain "@type"

      val clientInstanceData = json.toObject<ClientStatementData>()
      clientInstanceData shouldBe data
      val applePosture2 = clientInstanceData.posture as ApplePosture

      applePosture2.attStmt shouldBe applePosture1.attStmt
      applePosture2.authData shouldBe applePosture1.authData
      applePosture2.assertionAuthenticatorData shouldBe applePosture1.assertionAuthenticatorData
      applePosture2.keyId shouldBe applePosture1.keyId
      applePosture2.clientDataJson shouldBe applePosture1.clientDataJson
    }

    test("Serialize and deserialize Software posture") {
      val pkiData = generatePKIData()
      val nonceBytes = ByteArray(16).apply { SECURE_RANDOM.nextBytes(this) }
      val jwkThumbPrint = pkiData.jwkThumbPrint
      val publicKey = pkiData.publicKeyPEM
      val linux = LinuxProductId("packaging", "app-id")
      val attestationChallenge = calculateAttestationChallenge(jwkThumbPrint, nonceBytes)
      val softwarePosture1 = SoftwarePosture(linux, "demo_client", "0.2.0", "Linux", "6.12.54-linuxkit", "aarch64", publicKey, attestationChallenge)
      val data = ClientStatementData("jens", Platform.LINUX, PostureType.SOFTWARE, softwarePosture1, 4711L)
      val json = data.toJSON()

      json shouldContain "\"sub\":\"jens\""
      json shouldContain "\"platform\":\"linux\""
      json shouldContain "\"posture_type\":\"software\""
      json shouldNotContain "@type"

      val clientInstanceData = json.toObject<ClientStatementData>()
      clientInstanceData shouldBe data
      val softwarePosture2 = clientInstanceData.posture as SoftwarePosture

      softwarePosture2.publicKey shouldBe softwarePosture1.publicKey
      softwarePosture2.attestationChallenge shouldBe attestationChallenge
    }

    test("Serialize and deserialize TPM posture") {
      val keypair = generateKeyPair()
      val publicKeyBytes = keypair.public.encoded
      val publicKey = publicKeyBytes.toJSON()
      val windows = WindowsProductId("store", "family")
      val tpmPosture1 =
          TPMPosture(
              windows,
              "demo_client",
              "0.2.0",
              "Windows",
              "XP",
              "i686",
              publicKey,
              "»Quote«, Ain't that a hole in the boat?",
              "»Quote signature«",
              "»Event Log«",
              listOf("cert1", "cert2"),
          )
      val data = ClientStatementData("jens", Platform.LINUX, PostureType.TPM, tpmPosture1, 4711L)
      val json = data.toJSON()

      json shouldContain "\"sub\":\"jens\""
      json shouldContain "\"platform\":\"windows\""
      json shouldContain "\"posture_type\":\"tpm\""
      json shouldNotContain "@type"

      val clientInstanceData = json.toObject<ClientStatementData>()
      clientInstanceData shouldBe data
      val tpmPosture2 = clientInstanceData.posture as TPMPosture

      tpmPosture2.tpmAttestationKey shouldBe publicKey
      tpmPosture2.tpmQuote shouldBe tpmPosture1.tpmQuote
    }
  }
}
