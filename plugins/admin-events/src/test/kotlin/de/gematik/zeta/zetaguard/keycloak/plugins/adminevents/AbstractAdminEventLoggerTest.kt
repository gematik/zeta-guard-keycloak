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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents

import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.DefaultEMCreator
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import jakarta.persistence.Persistence
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession

abstract class AbstractAdminEventLoggerTest : FunSpec() {
    protected lateinit var entityManager: EntityManager
    protected lateinit var adminEventLogStorageService: AdminEventLogStorageService
    protected lateinit var eventLogger: AdminEventLoggerProvider

    protected val keycloakSession: KeycloakSession = mockk()
    protected val jpaConnectionProvider: JpaConnectionProvider = mockk()

    protected val adminEvent1 =
        AdminEvent().apply {
            realmName = "zetaguard"
            operationType = OperationType.UPDATE
            resourceType = ResourceType.ORGANIZATION
            resourcePath = "/users/123"
            time = 100000000L
            representation = """{"userId":"123"}"""
        }

    protected val adminEvent2 =
        AdminEvent().apply {
            realmName = "zetaguard"
            operationType = OperationType.ACTION
            resourceType = ResourceType.CLIENT_SCOPE
            resourcePath = "/users/4711"
            time = 100000111L
            representation = """{"foo":"bar"}"""
        }

    protected val adminEvent3 =
        AdminEvent().apply {
            realmName = "zetaguard"
            operationType = OperationType.ACTION
            resourceType = ResourceType.AUTH_FLOW
            resourcePath = "/users/4711"
            time = 200000111L
            representation = """{"jens":"hippe"}"""
        }

    init {
        beforeTest {
            entityManager = entityManagerFactory.createEntityManager().apply { transaction.begin() }

            every { keycloakSession.getProvider(JpaConnectionProvider::class.java) } returns
                jpaConnectionProvider
            every<EntityManager> { jpaConnectionProvider.entityManager } returns entityManager

            adminEventLogStorageService =
                AdminEventLogStorageService(DefaultEMCreator(keycloakSession))
            eventLogger = AdminEventLoggerProvider(adminEventLogStorageService)
        }

        afterTest {
            if (entityManager.isOpen) {
                entityManager.createNativeQuery("TRUNCATE TABLE admin_event_log").executeUpdate()
                entityManager.transaction.commit()
                entityManager.close()
            }
        }
    }

    protected fun <T> List<T>.second() = this[1]

    protected fun <T> List<T>.third() = this[2]

    protected fun newTransaction() {
        entityManager.flush()
        entityManager.transaction.commit()
        entityManager.transaction.begin()
        entityManager.clear()
    }

    companion object {
        @JvmStatic
        internal val entityManagerFactory = Persistence.createEntityManagerFactory("test")
    }
}
