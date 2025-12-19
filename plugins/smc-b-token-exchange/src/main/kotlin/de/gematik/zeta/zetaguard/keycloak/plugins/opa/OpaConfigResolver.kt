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
import org.jboss.logging.Logger
import org.keycloak.Config

object OpaConfigResolver {
  private val log: Logger = Logger.getLogger(OpaConfigResolver::class.java)

  fun normalize(config: OPAConfig): OPAConfig =
      config.copy(
          opaBaseUrl = config.opaBaseUrl.trimEnd('/'),
          decisionPath = if (config.decisionPath.startsWith("/")) config.decisionPath else "/${config.decisionPath}",
      )

  fun fromScope(scope: Config.Scope?, base: OPAConfig = OPAConfig()): OPAConfig {
    if (scope == null) return base

    val root = scope.root()
    fun fq(propKebab: String) = "spi-token-exchange-provider-$ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID-$propKebab"
    fun get(propKebab: String): String? = root[fq(propKebab)]
    fun getString(propKebab: String, def: String) = (get(propKebab) ?: def).trim()
    fun getInt(propKebab: String, def: Int) = get(propKebab)?.toIntOrNull() ?: def
    fun getBool(propKebab: String, def: Boolean) = get(propKebab)?.toBooleanStrictOrNull() ?: def

    val resolved =
        OPAConfig(
            enabled = getBool("opa-enabled", base.enabled),
            opaBaseUrl = getString("opa-base-url", base.opaBaseUrl),
            decisionPath = getString("decision-path", base.decisionPath),
            connectionTimeoutMs = getInt("connection-timeout-ms", base.connectionTimeoutMs),
            readTimeoutMs = getInt("read-timeout-ms", base.readTimeoutMs),
            failClosed = getBool("fail-closed", base.failClosed),
        )

    log.infof(
        "OPAConfig resolved (FQ-root): enabled=%s, baseUrl=%s, decisionPath=%s, connectionTimeoutMs=%d, readTimeoutMs=%d, failClosed=%s",
        resolved.enabled,
        resolved.opaBaseUrl,
        resolved.decisionPath,
        resolved.connectionTimeoutMs,
        resolved.readTimeoutMs,
        resolved.failClosed,
    )

    return resolved
  }
}
