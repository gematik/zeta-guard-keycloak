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
package de.gematik.zeta.zetaguard.keycloak.plugins.hsm.tokensigning

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import java.security.KeyStore
import org.keycloak.component.ComponentModel
import org.keycloak.provider.ProviderConfigProperty

class HsmTokenSigningKeyProviderFactoryTest : FunSpec() {

  init {

    test("getId returns expected provider ID") { HsmTokenSigningKeyProviderFactory().getId() shouldBe HsmTokenSigningKeyProviderFactory.PROVIDER_ID }

    test("getHelpText returns non-empty string") { HsmTokenSigningKeyProviderFactory().getHelpText() shouldNotBe "" }

    test("init and close are no-ops") {
      val f = HsmTokenSigningKeyProviderFactory()
      f.init(mockk(relaxed = true))
      f.close()
    }

    // ── Config properties (Admin UI support) ────────────────────────────────

    test("getConfigProperties returns endpoint, keyId, and priority") {
      val props = HsmTokenSigningKeyProviderFactory().getConfigProperties()
      props shouldHaveSize 3

      val names = props.map { it.name }
      names shouldBe
          listOf(
              HsmTokenSigningKeyProviderFactory.CONFIG_PRIORITY,
              HsmTokenSigningKeyProviderFactory.CONFIG_ENDPOINT,
              HsmTokenSigningKeyProviderFactory.CONFIG_KEY_ID,
          )
    }

    test("priority config has default value 200") {
      val priorityProp =
          HsmTokenSigningKeyProviderFactory().getConfigProperties().first { it.name == HsmTokenSigningKeyProviderFactory.CONFIG_PRIORITY }
      priorityProp.defaultValue shouldBe HsmTokenSigningKeyProviderFactory.HSM_PROVIDER_PRIORITY.toString()
    }

    test("all config properties are string type") {
      HsmTokenSigningKeyProviderFactory().getConfigProperties().forEach { prop -> prop.type shouldBe ProviderConfigProperty.STRING_TYPE }
    }

    // ── create ──────────────────────────────────────────────────────────────

    test("create returns HsmTokenSigningKeyProvider") {
      val factory = testableFactory()
      val model =
          ComponentModel().apply {
            id = "model-id"
            put(HsmTokenSigningKeyProviderFactory.CONFIG_ENDPOINT, "localhost:50051")
            put(HsmTokenSigningKeyProviderFactory.CONFIG_KEY_ID, "token-key.p256")
            put(HsmTokenSigningKeyProviderFactory.CONFIG_PRIORITY, "200")
          }

      factory.create(mockk(), model).shouldBeInstanceOf<HsmTokenSigningKeyProvider>()
    }

    test("create throws when endpoint is missing") {
      val factory = testableFactory()
      val model =
          ComponentModel().apply {
            id = "model-id"
            put(HsmTokenSigningKeyProviderFactory.CONFIG_KEY_ID, "token-key.p256")
          }

      val result = runCatching { factory.create(mockk(), model) }
      result.isFailure shouldBe true
      result.exceptionOrNull()!!.message shouldBe "HSM endpoint not configured"
    }

    test("create throws when keyId is missing") {
      val factory = testableFactory()
      val model =
          ComponentModel().apply {
            id = "model-id"
            put(HsmTokenSigningKeyProviderFactory.CONFIG_ENDPOINT, "localhost:50051")
          }

      val result = runCatching { factory.create(mockk(), model) }
      result.isFailure shouldBe true
      result.exceptionOrNull()!!.message shouldBe "HSM keyId not configured"
    }
  }

  /** Creates a factory with buildKeyStore stubbed to avoid real gRPC. */
  private fun testableFactory(): HsmTokenSigningKeyProviderFactory {
    return object : HsmTokenSigningKeyProviderFactory() {
      override fun buildKeyStore(endpoint: String, keyId: String): KeyStore {
        val kp = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(256) }.generateKeyPair()
        val cert = mockk<java.security.cert.X509Certificate>(relaxed = true) { every { publicKey } returns kp.public }
        return mockk {
          every { getKey(any(), any()) } returns kp.private
          every { getCertificate(any()) } returns cert
        }
      }
    }
  }
}
