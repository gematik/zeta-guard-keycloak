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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SMCB_KEYSTORE_LOCATION
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SMCB_KEYSTORE_PASSWORD
import de.gematik.zeta.zetaguard.keycloak.commons.server.SMCB_TOKEN_EXCHANGE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.setupBouncyCastle
import de.gematik.zeta.zetaguard.keycloak.pkcs12.KeystoreService
import de.gematik.zeta.zetaguard.keycloak.plugins.smcb.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.smcb.opa.OpaConfigResolver
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.lang.System.getenv
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory

private val SMCB_KEYSTORE_LOCATION
  get() = getenv(ENV_SMCB_KEYSTORE_LOCATION) ?: throw IllegalStateException("Missing configuration variable »$ENV_SMCB_KEYSTORE_LOCATION«")
private val SMCB_KEYSTORE_PASSWORD
  get() = getenv(ENV_SMCB_KEYSTORE_PASSWORD) ?: throw IllegalStateException("Missing configuration variable »$ENV_SMCB_KEYSTORE_PASSWORD«")

/**
 * External to internal token exchange provider for SMC-B created tokens.
 *
 * We try to use as much as possible from the standard V2 OIDC provider implementation.
 *
 * For details, see https://www.keycloak.org/securing-apps/token-exchange and
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5
 */
open class ZetaGuardTokenExchangeProviderFactory() : TokenExchangeProviderFactory {
  internal lateinit var keystoreService: KeystoreService
  internal var opaConfig: OPAConfig = OPAConfig()

  override fun create(session: KeycloakSession) = ZetaGuardTokenExchangeProvider(keystoreService, opaConfig)

  override fun init(config: Config.Scope) {
    // Load OPA config from Keycloak SPI scope for this provider
    // Keys: opaEnabled, opaBaseUrl, decisionPath, connectionTimeoutMs, readTimeoutMs, failClosed
    val resolver = OpaConfigResolver
    val raw = resolver.fromScope(config)
    opaConfig = resolver.normalize(raw)
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    // Order in java.security file is not being respected 🤷‍♂️
    // Maybe, because of DefaultCryptoProvider
    setupBouncyCastle()

    keystoreService = keystoreService()
  }

  override fun close() {}

  override fun getId() = SMCB_TOKEN_EXCHANGE_PROVIDER_ID

  // Higher priority than standard token exchange provider
  override fun order() = 30

  private fun keystoreService() = KeystoreService(keystoreLocation(), keystorePassword())

  private fun keystoreLocation(): InputStream {
    val file = File(SMCB_KEYSTORE_LOCATION)

    if (!file.exists() || !file.isFile) {
      throw IllegalStateException("Keystore not found at $SMCB_KEYSTORE_LOCATION")
    }

    return FileInputStream(file)
  }

  private fun keystorePassword() = SMCB_KEYSTORE_PASSWORD
}
