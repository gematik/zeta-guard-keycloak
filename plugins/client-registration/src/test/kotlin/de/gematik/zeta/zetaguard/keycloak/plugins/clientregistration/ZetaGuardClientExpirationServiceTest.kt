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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.collections.shouldHaveSize
import java.time.LocalDateTime
import kotlinx.datetime.DateTimePeriod

class ZetaGuardClientExpirationServiceTest : AbstractUserDataTest() {
  init {
    test("Find expired client registrations") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val clientData1 = dataService.createClientData("client1", ClientAuthMethod.SMC_B).apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData2 = dataService.createClientData("client2", ClientAuthMethod.SMC_B).apply { lastAccess = LocalDateTime.now().minusMinutes(12) }

      newTransaction()

      expirationService.findExpiredClients(DateTimePeriod(minutes = 13), 100).shouldBeEmpty()
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 8), 100) shouldContainExactly listOf(clientData2.id, clientData1.id)
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 11), 100) shouldContainExactly listOf(clientData2.id)
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 13), 100).shouldBeEmpty()
    }

    test("Expired clients and registrations are found oldest first, at most the given number") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val clients =
          (1..5).map { i ->
            dataService.createClientData("client$i", ClientAuthMethod.SMC_B).apply { lastAccess = LocalDateTime.now().minusMinutes(10L + i) }
          }

      newTransaction()

      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 8), 3) shouldContainExactly clients.reversed().take(3).map { it.id }
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 8), 100) shouldHaveSize 5
    }

    test("Expired valid clients are found oldest first, at most the given number") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val userData = dataService.createUserData("user1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clients =
          (1..5).map { i ->
            dataService.createClientData("client$i", ClientAuthMethod.SMC_B).apply {
              lastAccess = LocalDateTime.now().minusMinutes(10L + i)
              this.userData = userData
              attestationState = ClientAttestationState.VALID
            }
          }

      newTransaction()

      expirationService.findExpiredClients(DateTimePeriod(minutes = 8), 3) shouldContainExactly clients.reversed().take(3).map { it.id }
      expirationService.findExpiredClients(DateTimePeriod(minutes = 8), 100) shouldHaveSize 5
    }

    test("Expired users are found at most the given number") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      (1..5).forEach { i -> dataService.createUserData("user$i").apply { lastAccess = LocalDateTime.now().minusMinutes(10) } }

      newTransaction()

      expirationService.findExpiredUsers(DateTimePeriod(minutes = 9), 2) shouldHaveSize 2
      expirationService.findExpiredUsers(DateTimePeriod(minutes = 9), 100) shouldHaveSize 5
    }

    test("Find expired clients") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val userData1 = dataService.createUserData("user1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData1 = dataService.createClientData("client1", ClientAuthMethod.SMC_B).apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData2 = dataService.createClientData("client2", ClientAuthMethod.SMC_B).apply { lastAccess = LocalDateTime.now().minusMinutes(12) }

      clientData1.userData = userData1
      clientData2.userData = userData1
      clientData1.attestationState = ClientAttestationState.VALID
      clientData2.attestationState = ClientAttestationState.VALID

      newTransaction()

      expirationService.findExpiredClients(DateTimePeriod(minutes = 13), 100).shouldBeEmpty()
      expirationService.findExpiredClients(DateTimePeriod(minutes = 11), 100) shouldContainExactly listOf(clientData2.id)
      expirationService.findExpiredClients(DateTimePeriod(minutes = 8), 100) shouldContainExactly listOf(clientData2.id, clientData1.id)

      expirationService.findOldestClients(userData1.id) shouldContainExactly listOf(clientData2.id, clientData1.id)
    }

    test("User expiry") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val clientData2 = dataService.createClientData("client2", ClientAuthMethod.SMC_B)
      val userData1 = dataService.createUserData("user1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val userData2 = dataService.createUserData("user2").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }

      clientData2.userData = userData2

      newTransaction()

      expirationService.findExpiredUsers(DateTimePeriod(minutes = 13), 100).shouldBeEmpty()
      expirationService.findExpiredUsers(DateTimePeriod(minutes = 9), 100) shouldContainExactly listOf(userData1.id)
    }
  }
}
