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

import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.entityManager
import io.kotest.assertions.arrow.core.shouldBeLeft
import io.kotest.assertions.arrow.core.shouldBeRight
import org.hibernate.Session

class AdminEventLogVerificationTest : AbstractAdminEventLoggerTest() {
  private lateinit var adminEventLogVerificationService: AdminEventLogVerificationService

  init {
    beforeTest { adminEventLogVerificationService = AdminEventLogVerificationService(adminEventLogStorageService) }

    context("AdminEventLog verification") {
      test("valid chain") {
        adminEventLogVerificationService.verifyChain() shouldBeRight AdminEventLogEmpty

        storeEvents()

        adminEventLogVerificationService.verifyChain() shouldBeRight AdminEventLogValid
      }

      test("tampered hash chain") {
        storeEvents()

        val log2 = adminEventLogStorageService.findAll().second()
        val session = keycloakSession.entityManager.unwrap(Session::class.java)

        session.doWork { connection ->
          connection.createStatement().executeUpdate("UPDATE admin_event_log SET previous_hash = 'manipulatedHash' WHERE id = '${log2.id}'")
        }

        newTransaction()

        adminEventLogVerificationService.verifyChain() shouldBeLeft InvalidPreviousHash()
      }

      test("tampered event") {
        storeEvents()

        val log3 = adminEventLogStorageService.findAll().third()
        val session = keycloakSession.entityManager.unwrap(Session::class.java)

        session.doWork { connection ->
          connection.createStatement().executeUpdate("UPDATE admin_event_log SET event_data = 'new content' WHERE id = '${log3.id}'")
        }

        newTransaction()

        adminEventLogVerificationService.verifyChain() shouldBeLeft InvalidCurrentHash()
      }
    }
  }

  private fun storeEvents() {
    eventLogger.onEvent(adminEvent1, true)
    eventLogger.onEvent(adminEvent2, true)
    eventLogger.onEvent(adminEvent3, true)
  }
}
