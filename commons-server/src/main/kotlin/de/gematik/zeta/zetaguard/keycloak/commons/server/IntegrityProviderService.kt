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
package de.gematik.zeta.zetaguard.keycloak.commons.server

import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.configuration.SystemStateService
import de.spree.keycloak.commons.integrityProviderEnabled
import io.quarkus.runtime.Startup
import jakarta.enterprise.context.ApplicationScoped
import jakarta.inject.Inject

@ApplicationScoped
@Startup
class IntegrityProviderService {
  @Inject private lateinit var systemStateService: SystemStateService

  fun isIntegrityProviderEnabled() = integrityProviderEnabled

  fun isIntegrityProviderRunning() =
      systemStateService.currentSystemState().also {
        if (it != SystemState.OPERATIONAL) {
          logger.warn("⚠️ Spree integrity provider is enabled but not yet initialized! Current status: $it")
        }
      } == SystemState.OPERATIONAL
}
