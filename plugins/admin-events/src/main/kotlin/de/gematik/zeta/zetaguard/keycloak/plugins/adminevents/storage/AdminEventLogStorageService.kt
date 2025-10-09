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

import jakarta.persistence.EntityManager
import java.lang.System.getenv
import java.util.UUID
import org.jboss.logging.Logger
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession

typealias EntityManagerCreator = () -> EntityManager

class DefaultEMCreator(private val keycloakSession: KeycloakSession) : EntityManagerCreator {
    override fun invoke(): EntityManager = keycloakSession.entityManager
}

/**
 * Service for managing admin event logs in the Keycloak database.
 *
 * This service provides methods to retrieve the previous hash, find all admin event logs, and save
 * new admin event log entries.
 *
 * @property emCreator A lambda that provides an [EntityManager] instance for database operations.
 */
class AdminEventLogStorageService(emCreator: EntityManagerCreator) {
    private val entityManager by lazy { emCreator.invoke() }

    /**
     * Retrieves the previous hash from the most recent admin event log entry. If no entries exist,
     * it returns a predefined genesis hash.
     */
    fun previousHash(): String =
        entityManager
            .createQuery(
                "SELECT a.currentHash FROM AdminEventLog a ORDER BY a.createdAt DESC",
                String::class.java,
            )
            .setMaxResults(1)
            .resultList
            .firstOrNull() ?: GENESIS_PREVIOUS_HASH

    /**
     * Retrieves all admin event logs in historical order, i.e., from the oldest to the newest.
     *
     * This method is used to fetch the complete history of admin events.
     */
    fun findAll(): List<AdminEventLog> =
        entityManager
            .createQuery(
                "SELECT a FROM AdminEventLog a ORDER BY a.createdAt ASC",
                AdminEventLog::class.java,
            )
            .resultList

    fun saveAdminEventLog(adminEventLog: AdminEventLog) {
        entityManager.persist(adminEventLog)
        entityManager.flush()
    }

    companion object {
        @JvmStatic private val log = Logger.getLogger(AdminEventLogStorageService::class.java)

        @JvmStatic val GENESIS_PREVIOUS_HASH = getGenesisHash()

        private fun getGenesisHash(): String {
            var hash: String? = getenv("GENESIS_HASH")

            if (hash == null) {
                log.warn("No environment variable GENESIS_HASH set, creating a new initial hash")
                hash = (UUID.randomUUID().toString() + UUID.randomUUID()).replace("-", "")
            }

            return hash
        }
    }
}

val KeycloakSession.entityManager: EntityManager
    get() = getProvider(JpaConnectionProvider::class.java).entityManager
