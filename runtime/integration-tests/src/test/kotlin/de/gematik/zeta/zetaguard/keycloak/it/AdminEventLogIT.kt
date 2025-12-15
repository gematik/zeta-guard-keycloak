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
package de.gematik.zeta.zetaguard.keycloak.it

import com.fasterxml.jackson.databind.DeserializationFeature
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakAdminClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbhost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.dbport
import de.gematik.zeta.zetaguard.keycloak.it.Docker.jdbcUrl
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kchost
import de.gematik.zeta.zetaguard.keycloak.it.Docker.kcport
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.AdminEventLogValid
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.AdminEventLogVerificationService
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLog
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.ints.shouldBeGreaterThan
import io.kotest.matchers.shouldBe
import java.sql.DriverManager
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.representations.idm.UserRepresentation
import org.keycloak.util.JsonSerialization.mapper
import org.keycloak.util.JsonSerialization.readValue

/**
 * Test hash chain logging of admin events
 *
 * Should be first after [AAStartupIT], because it refers to testcontainer's host/ports
 */
@Order(1)
class AdminEventLogIT : FunSpec() {
  init {
    beforeSpec { mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false) }

    test("Check Keycloak setup") {
      KeycloakAdminClient(kchost, kcport).withKeycloak(clientId = ADMIN_CLIENT) {
        realm(ZETA_REALM).toRepresentation().displayName shouldBe "\uD835\uDF75-Guard"
      }
    }

    test("Check DB connection") { DriverManager.getConnection(jdbcUrl).use { it.isValid(1) shouldBe true } }

    test("Admin events are logged") {
      JpaEntityManagerFactory(dbhost, dbport, AdminEventLog::class.java).use {
        val adminEventLogStorageService = AdminEventLogStorageService { it.createEntityManager() }
        val verificationService = AdminEventLogVerificationService(adminEventLogStorageService)
        val initialNumber = adminEventLogStorageService.findAll().size

        initialNumber shouldBeGreaterThan 3
        val user2 = createUser(kchost, kcport)
        val logs = adminEventLogStorageService.findAll()
        logs.size shouldBe initialNumber + 2

        val adminEvent = readValue(logs.last().event, AdminEvent::class.java)
        adminEvent.realmName shouldBe ZETA_REALM
        adminEvent.operationType shouldBe OperationType.UPDATE
        adminEvent.resourceType shouldBe ResourceType.USER
        adminEvent.resourcePath shouldBe "users/${user2.id}"

        verificationService.verifyChain() shouldBeRight AdminEventLogValid
      }
    }
  }

  private fun createUser(kchost: String, kcport: Int): UserRepresentation =
      KeycloakAdminClient(kchost, kcport).withKeycloak(clientId = ADMIN_CLIENT) {
        val userData2 = UserData("user2", "geheim", "Jens", "Lehmann", "foo@bar.com")
        val realmResource = realm(ZETA_REALM)
        val usersResource = realmResource.users()

        usersResource.count() shouldBe 1
        KeycloakUtils.createUser(usersResource, userData2)
        usersResource.count() shouldBe 2
        val users = usersResource.list().groupBy { it.username }
        users["user2"]?.get(0)!!
      }
}
