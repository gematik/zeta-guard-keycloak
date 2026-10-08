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
@file:Suppress("SqlWithoutWhere")

package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.TABLE_NAME_CLIENT_DATA
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.TABLE_NAME_USER_DATA
import io.kotest.core.spec.style.FunSpec
import io.mockk.every
import io.mockk.mockk
import jakarta.persistence.EntityManager
import jakarta.persistence.Persistence
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.KeycloakSession

abstract class AbstractUserDataTest : FunSpec() {
  protected lateinit var entityManager: EntityManager
  protected lateinit var dataService: ZetaGuardDataService

  protected val keycloakSession: KeycloakSession = mockk()
  protected val jpaConnectionProvider: JpaConnectionProvider = mockk()

  init {
    beforeTest {
      entityManager = entityManagerFactory.createEntityManager().apply { transaction.begin() }
      dataService = ZetaGuardDataService { entityManager }

      every { keycloakSession.getProvider(JpaConnectionProvider::class.java) } returns jpaConnectionProvider
      every<EntityManager> { jpaConnectionProvider.entityManager } returns entityManager
    }

    afterTest {
      if (entityManager.isOpen) {
        entityManager.createNativeQuery("TRUNCATE TABLE $TABLE_NAME_CLIENT_DATA").executeUpdate()
        entityManager.createNativeQuery("DELETE FROM $TABLE_NAME_USER_DATA").executeUpdate()
        entityManager.transaction.commit()
        entityManager.close()
      }
    }
  }

  protected fun newTransaction() {
    entityManager.flush()
    entityManager.transaction.commit()
    entityManager.transaction.begin()
    entityManager.clear()
  }

  companion object {
    @JvmStatic private val entityManagerFactory = Persistence.createEntityManagerFactory("test")
  }
}
