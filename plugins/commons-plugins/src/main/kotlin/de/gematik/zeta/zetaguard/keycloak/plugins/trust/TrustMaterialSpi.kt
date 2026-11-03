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

import de.gematik.zeta.zetaguard.keycloak.commons.server.TRUST_MATERIAL_SPI_NAME
import org.keycloak.provider.Provider
import org.keycloak.provider.ProviderFactory
import org.keycloak.provider.Spi

/**
 * SPI giving every 𝛇-Guard plugin access to the one node-wide [TrustMaterial] snapshot.
 *
 * Keycloak has no built-in SPI for this, and loading the truststores once per plugin would multiply both the startup
 * cost and the reload jobs.
 */
class TrustMaterialSpi : Spi {
  override fun isInternal() = false

  override fun getName() = TRUST_MATERIAL_SPI_NAME

  override fun getProviderClass() = TrustMaterialProvider::class.java

  override fun getProviderFactoryClass() = TrustMaterialProviderFactory::class.java
}

/**
 * Per-session view on the trust material.
 *
 * [trustMaterial] returns whatever the reload has published most recently. Callers that need a consistent view for the
 * duration of a request should resolve it once and keep the result.
 */
class TrustMaterialProvider(private val current: () -> TrustMaterial) : Provider {
  fun trustMaterial(): TrustMaterial = current()

  override fun close() {
    // No-op
  }
}

interface TrustMaterialProviderFactory : ProviderFactory<TrustMaterialProvider>
