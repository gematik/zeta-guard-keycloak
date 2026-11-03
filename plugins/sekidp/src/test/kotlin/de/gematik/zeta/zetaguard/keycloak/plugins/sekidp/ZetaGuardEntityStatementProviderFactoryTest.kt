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
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe

private val REQUIRED_ENV = mapOf(
    "ENTITY_STATEMENT_CLIENT_NAME" to "zeta-guard",
    "ENTITY_STATEMENT_ORGANIZATION_NAME" to "zeta-guard",
    "ENTITY_STATEMENT_CONTACT_EMAIL" to "ops@example.com",
)

private fun requireFrom(): (String) -> String = { name ->
  REQUIRED_ENV[name] ?: error("Missing environment variable »$name«")
}

class ZetaGuardEntityStatementProviderFactoryTest : ZetaGuardFunSpec() {
  init {
    test("valid default config produces no warnings") {
      val cfg = resolveEntityStatementConfig(
          env = { _, default -> default },
          requireEnv = requireFrom(),
      )

      validateEntityStatementConfig(cfg).shouldBeEmpty()
    }

    test("valid custom config produces no warnings") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0", "2.0.0"),
          clientName = "My App",
          organizationName = "gematik GmbH",
          contactEmail = "ops@example.com",
          productTypeVersion = "2.1",
      )

      validateEntityStatementConfig(cfg).shouldBeEmpty()
    }

    test("unknown id_token_version produces a warning") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0", "3.0.0"),
          clientName = "zeta-guard",
          organizationName = "zeta-guard",
          contactEmail = "ops@example.com",
          productTypeVersion = "1.0.0",
      )

      val warnings = validateEntityStatementConfig(cfg)

      warnings shouldContainExactly listOf(
          "Entity statement: id_token_version »3.0.0« is not in the allowed set $ALLOWED_ID_TOKEN_VERSIONS",
      )
    }

    test("client_name violating the pattern produces a warning") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0"),
          clientName = "bad\$name",
          organizationName = "zeta-guard",
          contactEmail = "ops@example.com",
          productTypeVersion = "1.0.0",
      )

      val warnings = validateEntityStatementConfig(cfg)

      warnings shouldContainExactly listOf(
          "Entity statement: client_name »bad\$name« does not match the required pattern",
      )
    }

    test("organization_name violating the pattern produces a warning") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0"),
          clientName = "zeta-guard",
          organizationName = "bad\$org",
          contactEmail = "ops@example.com",
          productTypeVersion = "1.0.0",
      )

      val warnings = validateEntityStatementConfig(cfg)

      warnings shouldContainExactly listOf(
          "Entity statement: organization_name »bad\$org« does not match the required pattern",
      )
    }

    test("contact email without '@' produces a warning") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0"),
          clientName = "zeta-guard",
          organizationName = "zeta-guard",
          contactEmail = "no-at-sign",
          productTypeVersion = "1.0.0",
      )

      val warnings = validateEntityStatementConfig(cfg)

      warnings shouldContainExactly listOf(
          "Entity statement: contact email »no-at-sign« does not contain '@'",
      )
    }

    test("multiple violations produce multiple warnings") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("9.9.9"),
          clientName = "bad\$name",
          organizationName = "bad\$org",
          contactEmail = "no-at-sign",
          productTypeVersion = "1.0.0",
      )

      val warnings = validateEntityStatementConfig(cfg)

      warnings.size shouldBe 4
    }

    test("names with umlauts and special characters are accepted by the pattern") {
      val cfg = EntityStatementConfig(
          idTokenVersions = listOf("1.0.0"),
          clientName = "Ärzte-Netz Süd/West",
          organizationName = "Über.org +special*",
          contactEmail = "ops@example.com",
          productTypeVersion = "1.0.0",
      )

      validateEntityStatementConfig(cfg).shouldBeEmpty()
    }
  }
}
