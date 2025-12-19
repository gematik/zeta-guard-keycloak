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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import org.keycloak.Config

class OpaConfigResolverTest :
    StringSpec({
      "normalize trims base url and ensures leading slash" {
        val cfg = OPAConfig(opaBaseUrl = "http://opa:8181/", decisionPath = "v1/data/x")
        val norm = OpaConfigResolver.normalize(cfg)
        norm.opaBaseUrl shouldBe "http://opa:8181"
        norm.decisionPath shouldBe "/v1/data/x"
      }

      "fromScope resolves fully-qualified root keys" {
        val prefix = "spi-token-exchange-provider-$ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID-"
        val scope =
            dummyScope(
                mapOf(
                    prefix + "opa-enabled" to "true",
                    prefix + "opa-base-url" to " http://env-opa:8181/ ",
                    prefix + "decision-path" to " v1/data/env/decision ",
                    prefix + "connection-timeout-ms" to "3333",
                    prefix + "read-timeout-ms" to "4444",
                    prefix + "fail-closed" to "true",
                )
            )

        val cfg = OpaConfigResolver.normalize(OpaConfigResolver.fromScope(scope, OPAConfig(enabled = false)))
        cfg.enabled shouldBe true
        cfg.opaBaseUrl shouldBe "http://env-opa:8181"
        cfg.decisionPath shouldBe "/v1/data/env/decision"
        cfg.connectionTimeoutMs shouldBe 3333
        cfg.readTimeoutMs shouldBe 4444
        cfg.failClosed shouldBe true
      }
    })

private fun dummyScope(values: Map<String, String>): Config.Scope =
    object : Config.Scope {
      override fun get(name: String): String? = values[name]

      override fun get(name: String, defaultValue: String?): String? = values[name] ?: defaultValue

      override fun getArray(name: String): Array<String>? = null

      override fun getInt(name: String): Int = values[name]?.toIntOrNull() ?: 0

      override fun getInt(name: String, defaultValue: Int): Int = values[name]?.toIntOrNull() ?: defaultValue

      override fun getBoolean(name: String): Boolean = values[name]?.toBooleanStrictOrNull() ?: false

      override fun getBoolean(name: String, defaultValue: Boolean): Boolean = values[name]?.toBooleanStrictOrNull() ?: defaultValue

      override fun getLong(name: String): Long = values[name]?.toLongOrNull() ?: 0L

      override fun getLong(name: String, defaultValue: Long): Long = values[name]?.toLongOrNull() ?: defaultValue

      @Deprecated("Deprecated in Java") override fun getPropertyNames(): MutableSet<String> = values.keys.toMutableSet()

      override fun root(): Config.Scope = this

      override fun scope(vararg name: String): Config.Scope? = null
    }
