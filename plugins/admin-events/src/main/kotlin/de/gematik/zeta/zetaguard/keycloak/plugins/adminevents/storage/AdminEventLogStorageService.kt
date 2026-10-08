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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_GENESIS_HASH
import de.gematik.zeta.zetaguard.keycloak.commons.server.safeGetenv
import de.gematik.zeta.zetaguard.keycloak.jpa.EntityManagerCreator
import jakarta.persistence.EntityManager

/**
 * Service for managing admin event logs in the Keycloak database.
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26269
 *
 * This service provides methods to retrieve the previous hash, find all admin event logs, and save new admin event log entries.
 */
class AdminEventLogStorageService
/** @param emCreator A lambda that provides an [EntityManager] instance for database operations. */
constructor(emCreator: EntityManagerCreator) {
  private val entityManager by lazy { emCreator.invoke() }

  /**
   * Retrieves the previous hash from the most recent admin event log entry.
   *
   * If no entries exist, it returns a genesis hash from memory.
   */
  fun previousHash(): String =
      entityManager
          .createQuery("SELECT a.currentHash FROM AdminEventLog a ORDER BY a.createdAt DESC", String::class.java)
          .setMaxResults(1)
          .resultList
          .firstOrNull() ?: GENESIS_HASH

  /**
   * Retrieves all admin event logs in historical order, i.e., from the oldest to the latest.
   *
   * This method is used to fetch the complete history of admin events.
   */
  fun findAll(): List<AdminEventLog> =
      entityManager.createQuery("SELECT a FROM AdminEventLog a ORDER BY a.createdAt ASC", AdminEventLog::class.java).resultList

  fun saveAdminEventLog(adminEventLog: AdminEventLog) {
    entityManager.persist(adminEventLog)
    entityManager.flush()
  }

  companion object {
    const val GENESIS_MARKER = ENV_GENESIS_HASH

    val GENESIS_HASH: String by lazy { safeGetenv(ENV_GENESIS_HASH) }
  }
}
