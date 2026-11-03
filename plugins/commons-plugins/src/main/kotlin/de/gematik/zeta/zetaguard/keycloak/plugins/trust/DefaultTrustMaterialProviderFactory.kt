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
package de.gematik.zeta.zetaguard.keycloak.plugins.trust

import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import de.gematik.zeta.zetaguard.keycloak.commons.server.TRUST_MATERIAL_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

/**
 * Loads the SMC-B, TPM, OCSP, Apple and Google truststores and keeps them current via [scheduleTrustMaterialReload].
 *
 * The material is loaded in [init] rather than [postInit]: Keycloak calls `init` on every factory before it calls
 * `postInit` on any of them, so consumers may resolve the material from their own `postInit` regardless of the order in
 * which factories are initialized. A missing or unparsable truststore therefore fails the startup, as before.
 */
open class DefaultTrustMaterialProviderFactory : TrustMaterialProviderFactory {
  /**
   * All truststores as one immutable snapshot, swapped as a single reference by [scheduleTrustMaterialReload].
   *
   * `@Volatile` is what makes that swap safe without locking.
   */
  @Volatile
  internal lateinit var trustMaterial: TrustMaterial

  override fun create(session: KeycloakSession) = TrustMaterialProvider { trustMaterial }

  override fun init(config: Config.Scope) {
    logger.info("🛠️ Initializing 𝛇-Guard TrustMaterialProviderFactory...")

    // TrustMaterial is parsed with BouncyCastle
    setupSecurityProviders()

    trustMaterial = TrustMaterial.load()

    logger.info("🔐 Loaded trust material (${trustMaterial.describe()})")

    if (trustMaterial.ocsp == null) {
      logger.warn("⚠️ OCSP checking disabled, Keystore or Meta File unavailable")
    }

    if (trustMaterial.aliasesWithoutMeta.isNotEmpty()) {
      logger.warn("⚠️ No meta entry for ${trustMaterial.aliasesWithoutMeta}, the revocation check fails open for those")
    }
  }

  override fun postInit(factory: KeycloakSessionFactory) {
    scheduleTrustMaterialReload(factory, { trustMaterial }, { trustMaterial = it })
  }

  override fun getId() = TRUST_MATERIAL_PROVIDER_ID

  override fun close() {
    // No-op
  }
}
