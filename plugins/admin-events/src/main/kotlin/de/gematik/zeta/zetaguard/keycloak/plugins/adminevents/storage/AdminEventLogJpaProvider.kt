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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage

import org.keycloak.connections.jpa.entityprovider.JpaEntityProvider

/*
 * Zeta Guard Admin Event Log JPA Provider
 *
 * This provider registers the AdminEventLog entity for JPA persistence.
 * It is used to store and retrieve admin event logs in the Keycloak database.
 */
class AdminEventLogJpaProvider : JpaEntityProvider {
  override fun getEntities(): List<Class<*>> = listOf(AdminEventLog::class.java)

  override fun getChangelogLocation() = "META-INF/jpa-changelog.26.3.2.xml"

  override fun getFactoryId() = ADMIN_EVENTS_JPA_PROVIDER_ID

  override fun close() {}
}
