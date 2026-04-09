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
package de.gematik.zeta.zetaguard.keycloak.plugins.hsmproxy

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.mockk
import java.security.KeyStore

class HsmProxyKeycloakFactoryTest : FunSpec() {

  init {
    test("getId returns zeta-hsm-proxy") { HsmProxyKeycloakFactory().getId() shouldBe "zeta-hsm-proxy" }

    test("create returns HsmProxyKeycloakProvider") {
      HsmProxyKeycloakFactory().create(mockk()).shouldBeInstanceOf<HsmProxyKeycloakProvider>()
    }

    test("init and close are no-ops") {
      val factory = HsmProxyKeycloakFactory()
      factory.init(mockk(relaxed = true))
      factory.close()
    }

    test("postInit calls buildKeyStore when both env vars are set") {
      var buildKeyStoreCalled = false
      val factory =
          object : HsmProxyKeycloakFactory() {
            override fun getenv(name: String) =
                when (name) {
                  ENV_HSM_PROXY_ENDPOINT -> "localhost:50051"
                  ENV_HSM_PROXY_KEY_ID -> "test-key.p256"
                  else -> null
                }

            override fun buildKeyStore(endpoint: String, keyId: String): KeyStore {
              buildKeyStoreCalled = true
              return mockk(relaxed = true)
            }
          }

      factory.postInit(mockk())

      buildKeyStoreCalled shouldBe true
    }

    test("postInit skips when HSM_PROXY_ENDPOINT is not set") {
      val factory = factoryWithEnv(endpoint = null, keyId = "test-key.p256")

      factory.postInit(mockk())

      factory.buildKeyStoreCalled shouldBe false
    }

    test("postInit skips when HSM_PROXY_KEY_ID is not set") {
      val factory = factoryWithEnv(endpoint = "localhost:50051", keyId = null)

      factory.postInit(mockk())

      factory.buildKeyStoreCalled shouldBe false
    }

    test("postInit skips when both env vars are absent") {
      val factory = factoryWithEnv(endpoint = null, keyId = null)

      factory.postInit(mockk())

      factory.buildKeyStoreCalled shouldBe false
    }
  }

  /**
   * Returns a factory that injects [endpoint] and [keyId] via [HsmProxyKeycloakFactory.getenv]
   * (avoids mocking [System], which causes [StackOverflowError] on JDK 21 with Mockk) and stubs
   * [HsmProxyKeycloakFactory.buildKeyStore] to track whether it was called.
   */
  private fun factoryWithEnv(endpoint: String?, keyId: String?) =
      object : HsmProxyKeycloakFactory() {
        var buildKeyStoreCalled = false

        override fun getenv(name: String) =
            when (name) {
              ENV_HSM_PROXY_ENDPOINT -> endpoint
              ENV_HSM_PROXY_KEY_ID -> keyId
              else -> null
            }

        override fun buildKeyStore(endpoint: String, keyId: String): KeyStore {
          buildKeyStoreCalled = true
          return mockk(relaxed = true)
        }
      }
}
