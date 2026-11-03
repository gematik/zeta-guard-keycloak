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
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain

private val REQUIRED_ENV = mapOf(
    "ENTITY_STATEMENT_CLIENT_NAME" to "zeta-guard",
    "ENTITY_STATEMENT_ORGANIZATION_NAME" to "zeta-guard",
    "ENTITY_STATEMENT_CONTACT_EMAIL" to "noreply@localhost",
)

private fun requireFrom(env: Map<String, String>): (String) -> String = { name ->
  env[name] ?: error("Missing environment variable »$name«")
}

class ZetaGuardEntityStatementProviderTest : ZetaGuardFunSpec() {
  init {
    test("defaults are used when no optional environment variables are set") {
      val cfg = resolveEntityStatementConfig(
          env = { _, default -> default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.idTokenVersions shouldBe listOf("1.0.0")
      cfg.clientName shouldBe "zeta-guard"
      cfg.organizationName shouldBe "zeta-guard"
      cfg.contactEmail shouldBe "noreply@localhost"
      cfg.productTypeVersion shouldBe "1.0.0"
      cfg.redirectUris shouldBe emptyList()
    }

    test("custom environment values are picked up") {
      val env = mapOf(
          "ENTITY_STATEMENT_ID_TOKEN_VERSION" to "2.0.0",
          "ENTITY_STATEMENT_CLIENT_NAME" to "my-app",
          "ENTITY_STATEMENT_ORGANIZATION_NAME" to "my-org",
          "ENTITY_STATEMENT_CONTACT_EMAIL" to "ops@example.com",
          "ENTITY_STATEMENT_PRODUCT_TYPE_VERSION" to "2.1",
      )
      val cfg = resolveEntityStatementConfig(
          env = { name, default -> env[name] ?: default },
          requireEnv = requireFrom(env),
      )

      cfg.idTokenVersions shouldBe listOf("2.0.0")
      cfg.clientName shouldBe "my-app"
      cfg.organizationName shouldBe "my-org"
      cfg.contactEmail shouldBe "ops@example.com"
      cfg.productTypeVersion shouldBe "2.1"
    }

    test("comma-separated id_token_version is split into a list") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default -> if (name == "ENTITY_STATEMENT_ID_TOKEN_VERSION") "1.0.0, 2.0.0" else default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.idTokenVersions shouldBe listOf("1.0.0", "2.0.0")
    }

    test("trailing comma and whitespace in id_token_version are handled") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default -> if (name == "ENTITY_STATEMENT_ID_TOKEN_VERSION") " 1.0.0 , 2.0.0 , " else default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.idTokenVersions shouldBe listOf("1.0.0", "2.0.0")
    }

    test("product_type_version defaults to 1.0.0 when not configured") {
      val cfg = resolveEntityStatementConfig(
          env = { _, default -> default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.productTypeVersion shouldBe "1.0.0"
    }

    test("product_type_version can be overridden via environment variable") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default -> if (name == "ENTITY_STATEMENT_PRODUCT_TYPE_VERSION") "99.0" else default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.productTypeVersion shouldBe "99.0"
    }

    test("comma-separated redirect_uris are split into a list") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default ->
            if (name == "ENTITY_STATEMENT_REDIRECT_URIS") "https://a.example/cb,https://b.example/cb" else default
          },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.redirectUris shouldBe listOf("https://a.example/cb", "https://b.example/cb")
    }

    test("whitespace, empty entries and duplicates in redirect_uris are dropped") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default ->
            if (name == "ENTITY_STATEMENT_REDIRECT_URIS") " https://a.example/cb , ,https://b.example/cb,https://a.example/cb, " else default
          },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.redirectUris shouldBe listOf("https://a.example/cb", "https://b.example/cb")
    }

    test("blank redirect_uris yield an empty list, so they are derived from the realm's SekIDP clients") {
      val cfg = resolveEntityStatementConfig(
          env = { name, default -> if (name == "ENTITY_STATEMENT_REDIRECT_URIS") " , " else default },
          requireEnv = requireFrom(REQUIRED_ENV),
      )

      cfg.redirectUris shouldBe emptyList()
    }

    test("configured redirect_uris replace the SekIDP clients' redirect URIs completely") {
      var derivedCalled = false
      val uris = effectiveRedirectUris(listOf("https://a.example/cb")) {
        derivedCalled = true
        listOf("https://client.example/cb")
      }

      uris shouldBe listOf("https://a.example/cb")
      derivedCalled shouldBe false
    }

    test("without configured redirect_uris the SekIDP clients' redirect URIs are used") {
      effectiveRedirectUris(emptyList()) { listOf("https://client.example/cb") } shouldBe listOf("https://client.example/cb")
    }

    test("missing ENTITY_STATEMENT_CLIENT_NAME throws") {
      shouldThrow<IllegalStateException> {
        resolveEntityStatementConfig(
            requireEnv = requireFrom(REQUIRED_ENV - "ENTITY_STATEMENT_CLIENT_NAME"),
        )
      }.message shouldContain "ENTITY_STATEMENT_CLIENT_NAME"
    }

    test("missing ENTITY_STATEMENT_ORGANIZATION_NAME throws") {
      shouldThrow<IllegalStateException> {
        resolveEntityStatementConfig(
            requireEnv = requireFrom(REQUIRED_ENV - "ENTITY_STATEMENT_ORGANIZATION_NAME"),
        )
      }.message shouldContain "ENTITY_STATEMENT_ORGANIZATION_NAME"
    }

    test("missing ENTITY_STATEMENT_CONTACT_EMAIL throws") {
      shouldThrow<IllegalStateException> {
        resolveEntityStatementConfig(
            requireEnv = requireFrom(REQUIRED_ENV - "ENTITY_STATEMENT_CONTACT_EMAIL"),
        )
      }.message shouldContain "ENTITY_STATEMENT_CONTACT_EMAIL"
    }
  }
}
