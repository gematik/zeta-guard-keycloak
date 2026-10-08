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
package de.gematik.zeta.zetaguard.keycloak.plugins.token_exchange

import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import de.gematik.zeta.zetaguard.keycloak.commons.OcspConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.ocsp.OcspConfigResolver
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaConfigResolver
import io.quarkus.arc.Arc
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.protocol.oidc.TokenExchangeProviderFactory

/**
 * External to internal token exchange provider for SMC-B created tokens.
 *
 * We try to use as much as possible from the standard V2 OIDC provider implementation.
 *
 * For details, see https://www.keycloak.org/securing-apps/token-exchange and
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5
 */
open class ZetaGuardTokenExchangeProviderFactory : TokenExchangeProviderFactory {
  /**
   * All truststores as one immutable snapshot, swapped as a single reference by [scheduleTrustMaterialReload].
   *
   * `@Volatile` is what makes that swap safe without locking. [create] hands the provider a getter rather than the
   * snapshot itself; the provider resolves it once, so a running token exchange keeps the material it started with
   * while the next one picks up whatever has been published since.
   */
  @Volatile internal lateinit var trustMaterial: TrustMaterial

  internal var opaConfig: OPAConfig = OPAConfig()
  internal var ocspConfig: OcspConfig = OcspConfig()
  internal lateinit var integrityProviderService: IntegrityProviderService

  override fun create(session: KeycloakSession) =
      ZetaGuardTokenExchangeProvider(
          integrityProviderService,
          ZetaGuardDataService(DefaultEMCreator(session)),
          { trustMaterial },
          opaConfig,
          ocspConfig,
      )

  override fun init(config: Config.Scope) {
    // Load OPA config from Keycloak SPI scope for this provider
    // Keys: opaBaseUrl, decisionPath, connectionTimeoutMs, readTimeoutMs
    // Values are set via environment variables, e.g. KC_SPI_TOKEN_EXCHANGE_PROVIDER_ZETA_SMC_B_TOKEN_EXCHANGE_OPA_ENABLED
    val resolver = OpaConfigResolver
    val raw = resolver.fromScope(config)

    opaConfig = resolver.normalize(raw)
    ocspConfig = OcspConfigResolver.fromScope(config)
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    logger.info("🛠️ Initializing 𝛇-Guard TokenExchangeProviderFactory...")

    // Order in java.security file is not respected by KC/Quarkus 🤷‍♂️
    // Set BC as default provider
    setupSecurityProviders()

    trustMaterial = TrustMaterial.load()
    integrityProviderService = Arc.container().instance(IntegrityProviderService::class.java).get()

    if (trustMaterial.ocsp == null) {
      logger.warn("OCSP checking disabled, Keystore or Meta File unavailable")
    }

    if (trustMaterial.aliasesWithoutMeta.isNotEmpty()) {
      logger.warn("No meta entry for ${trustMaterial.aliasesWithoutMeta}, the revocation check fails open for those")
    }

    scheduleTrustMaterialReload(factory, { trustMaterial }, { trustMaterial = it })
  }

  override fun getId() = ZETAGUARD_TOKEN_EXCHANGE_PROVIDER_ID

  // Higher priority than standard token exchange provider
  override fun order() = 30

  override fun close() {
    // No-op
  }
}
