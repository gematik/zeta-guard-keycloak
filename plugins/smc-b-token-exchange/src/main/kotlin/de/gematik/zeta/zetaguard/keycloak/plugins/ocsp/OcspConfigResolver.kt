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
package de.gematik.zeta.zetaguard.keycloak.plugins.ocsp

import de.gematik.zeta.zetaguard.keycloak.commons.OcspConfig
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID
import org.jboss.logging.Logger
import org.keycloak.Config

object OcspConfigResolver {
  private val log: Logger = Logger.getLogger(OcspConfigResolver::class.java)

  fun fromScope(scope: Config.Scope?, base: OcspConfig = OcspConfig()): OcspConfig {
    if (scope == null) return base

    val root = scope.root()
    fun fq(propKebab: String) = "spi-token-exchange-provider-$ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID-$propKebab"
    fun getInt(propKebab: String, def: Int) = root[fq(propKebab)]?.toIntOrNull() ?: def
    fun getBoolean(propKebab: String, def: Boolean) = root[fq(propKebab)]?.toBooleanStrictOrNull() ?: def

    val resolved =
        OcspConfig(
            connectTimeoutMs = getInt("ocsp-connect-timeout-ms", base.connectTimeoutMs),
            readTimeoutMs = getInt("ocsp-read-timeout-ms", base.readTimeoutMs),
            failClosed = getBoolean("ocsp-fail-closed", base.failClosed),
        )

    log.infof(
        "OcspConfig resolved (FQ-root): connectTimeoutMs=%d, readTimeoutMs=%d, failClosed=%b",
        resolved.connectTimeoutMs,
        resolved.readTimeoutMs,
        resolved.failClosed,
    )

    return resolved
  }
}
