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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardUserData
import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider

/*
 * Zeta Guard JPA Provider
 */
class ZetaGuardDataJpaProvider : JpaEntityProvider {
  override fun getEntities(): List<Class<*>> = listOf(ZetaGuardUserData::class.java, ZetaGuardClientData::class.java)

  override fun getChangelogLocation() = "META-INF/jpa-changelog-26.6.3.xml"

  override fun getFactoryId() = JPA_PROVIDER_ID

  override fun close() {
    // No-op
  }
}
