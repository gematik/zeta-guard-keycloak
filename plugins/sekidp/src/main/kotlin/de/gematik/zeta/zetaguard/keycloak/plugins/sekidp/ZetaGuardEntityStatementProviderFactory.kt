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

import de.gematik.zeta.zetaguard.keycloak.commons.server.OPENID_FEDERATION_ALIAS
import de.gematik.zeta.zetaguard.keycloak.commons.server.OidcFlowSettings
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.wellknown.WellKnownProvider
import org.keycloak.wellknown.WellKnownProviderFactory

private val logger: Logger = Logger.getLogger(ZetaGuardEntityStatementProviderFactory::class.java)

internal val ALLOWED_ID_TOKEN_VERSIONS = setOf("1.0.0", "2.0.0")

// A_23034-02
internal val METADATA_NAME_PATTERN = Regex("""^[à-üÀ-Üß\w \-.+*/]{1,128}$""")

internal fun validateEntityStatementConfig(cfg: EntityStatementConfig): List<String> = buildList {
  cfg.idTokenVersions.filter { it !in ALLOWED_ID_TOKEN_VERSIONS }.forEach {
    add("Entity statement: id_token_version »$it« is not in the allowed set $ALLOWED_ID_TOKEN_VERSIONS")
  }
  if (!METADATA_NAME_PATTERN.matches(cfg.clientName)) {
    add("Entity statement: client_name »${cfg.clientName}« does not match the required pattern")
  }
  if (!METADATA_NAME_PATTERN.matches(cfg.organizationName)) {
    add("Entity statement: organization_name »${cfg.organizationName}« does not match the required pattern")
  }
  if ('@' !in cfg.contactEmail) {
    add("Entity statement: contact email »${cfg.contactEmail}« does not contain '@'")
  }
}

class ZetaGuardEntityStatementProviderFactory : WellKnownProviderFactory {
  override fun create(session: KeycloakSession): WellKnownProvider? =
      if (OidcFlowSettings.isEnabled()) ZetaGuardEntityStatementProvider(session, federationMasterConfig.fedmasterUrl) else null

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    if (!OidcFlowSettings.isEnabled()) return

    federationMasterConfig.fedmasterUrl

    val cfg = entityStatementConfig
    // A static list replaces the SekIDP clients' redirect URIs, so a client registered later is missing from the statement.
    val redirectUris =
        if (cfg.redirectUris.isEmpty()) "<derived from SekIDP clients>"
        else "${cfg.redirectUris} (static, replaces the SekIDP clients' redirect URIs)"

    logger.infof(
        "Entity statement config: id_token_version_supported=%s, client_name=%s, organization_name=%s, contact=%s, product_type_version=%s, " +
            "redirect_uris=%s",
        cfg.idTokenVersions, cfg.clientName, cfg.organizationName, cfg.contactEmail, cfg.productTypeVersion, redirectUris)

    val warnings = validateEntityStatementConfig(cfg)
    warnings.forEach { logger.warnf(it) }
    check(warnings.isEmpty()) { "Entity statement configuration is invalid: ${warnings.joinToString("; ")}" }
  }

  override fun close() {
    // No-op
  }

  override fun getId() = "zeta-guard-entity-statement"

  override fun getAlias() = OPENID_FEDERATION_ALIAS
}
