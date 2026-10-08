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

import io.kotest.assertions.throwables.shouldThrow
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldContain
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import java.security.KeyStore
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.crypto.Algorithm
import org.keycloak.crypto.KeyUse
import org.keycloak.models.KeycloakSession
import org.keycloak.provider.ProviderConfigProperty

class HsmTokenSigningKeyProviderFactoryTest : FunSpec() {

  init {

    test("getId returns expected provider ID") { HsmTokenSigningKeyProviderFactory().getId() shouldBe HsmTokenSigningKeyProviderFactory.PROVIDER_ID }

    test("getHelpText returns non-empty string") { HsmTokenSigningKeyProviderFactory().getHelpText() shouldNotBe "" }

    test("init reads failClosed=true by default and close is a no-op") {
      val f = HsmTokenSigningKeyProviderFactory()
      val scope = mockk<Config.Scope> { every { getBoolean(HsmTokenSigningKeyProviderFactory.CONFIG_FAIL_CLOSED, true) } returns true }
      f.init(scope)
      f.failClosed shouldBe true
      f.close()
    }

    test("init reads failClosed=false from SPI scope (operator opt-out)") {
      val f = HsmTokenSigningKeyProviderFactory()
      val scope = mockk<Config.Scope> { every { getBoolean(HsmTokenSigningKeyProviderFactory.CONFIG_FAIL_CLOSED, true) } returns false }
      f.init(scope)
      f.failClosed shouldBe false
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

    // ── createFallbackKeys (fail-closed guard) ──────────────────────────────

    test("createFallbackKeys returns false when failClosed=false (operator opt-out)") {
      val factory = guardFactory(failClosed = false)
      factory.createFallbackKeys(mockk(), KeyUse.SIG, Algorithm.ES256) shouldBe false
    }

    test("createFallbackKeys returns false when realm has no HSM provider component (bootstrap fall-through)") {
      val factory = guardFactory(failClosed = true, realmHasHsmProvider = false)
      factory.createFallbackKeys(mockk(), KeyUse.SIG, Algorithm.ES256) shouldBe false
    }

    test("createFallbackKeys returns false for non-SIG key use (e.g. ENC)") {
      val factory = guardFactory(failClosed = true)
      factory.createFallbackKeys(mockk(), KeyUse.ENC, Algorithm.ES256) shouldBe false
    }

    test("createFallbackKeys throws HsmUnavailableException for ES256 SIG when failClosed") {
      val factory = guardFactory(failClosed = true)
      val ex = shouldThrow<HsmUnavailableException> { factory.createFallbackKeys(mockk(), KeyUse.SIG, Algorithm.ES256) }
      ex.message shouldContain "ES256"
      ex.message shouldContain "Software fallback is disabled by policy"
    }

    test("createFallbackKeys throws HsmUnavailableException for RS256 SIG when failClosed (no RSA software fallback)") {
      val factory = guardFactory(failClosed = true)
      val ex = shouldThrow<HsmUnavailableException> { factory.createFallbackKeys(mockk(), KeyUse.SIG, Algorithm.RS256) }
      ex.message shouldContain "RS256"
    }

    test("createFallbackKeys throws HsmUnavailableException for any SIG algorithm when failClosed") {
      val factory = guardFactory(failClosed = true)
      listOf(Algorithm.PS256, Algorithm.ES384, "EdDSA").forEach { alg ->
        shouldThrow<HsmUnavailableException> { factory.createFallbackKeys(mockk(), KeyUse.SIG, alg) }
      }
    }
  }

  /** Test factory: overrides `hsmEnforcingRealmName` to bypass mockk's KeycloakContext proxy issue. */
  private fun guardFactory(failClosed: Boolean, realmHasHsmProvider: Boolean = true): HsmTokenSigningKeyProviderFactory =
      object : HsmTokenSigningKeyProviderFactory() {
            override fun hsmEnforcingRealmName(session: KeycloakSession): String? = if (realmHasHsmProvider) "<test>" else null
          }
          .also { it.failClosed = failClosed }

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
