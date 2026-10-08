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
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import java.time.LocalDateTime
import kotlinx.datetime.DateTimePeriod

class ZetaGuardClientExpirationServiceTest : AbstractUserDataTest() {
  init {
    test("Find expired client registrations") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val clientData1 = dataService.createClientData("client1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData2 = dataService.createClientData("client2").apply { lastAccess = LocalDateTime.now().minusMinutes(12) }

      newTransaction()

      expirationService.findExpiredClients(DateTimePeriod(minutes = 13)).shouldBeEmpty()
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 8)) shouldBe listOf(clientData2.id, clientData1.id)
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 11)) shouldBe listOf(clientData2.id)
      expirationService.findExpiredClientRegistrations(DateTimePeriod(minutes = 13)).shouldBeEmpty()
    }

    test("Find expired clients") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val userData1 = dataService.createUserData("user1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData1 = dataService.createClientData("client1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val clientData2 = dataService.createClientData("client2").apply { lastAccess = LocalDateTime.now().minusMinutes(12) }

      clientData1.userData = userData1
      clientData2.userData = userData1
      clientData1.attestationState = ClientAttestationState.VALID
      clientData2.attestationState = ClientAttestationState.VALID

      newTransaction()

      expirationService.findExpiredClients(DateTimePeriod(minutes = 13)).shouldBeEmpty()
      expirationService.findExpiredClients(DateTimePeriod(minutes = 11)) shouldBe listOf(clientData2.id)
      expirationService.findExpiredClients(DateTimePeriod(minutes = 8)) shouldBe listOf(clientData2.id, clientData1.id)

      expirationService.findOldestClients(userData1.id) shouldBe listOf(clientData2.id, clientData1.id)
    }

    test("User expiry") {
      val expirationService = ZetaGuardClientExpirationDao { entityManager }
      val clientData2 = dataService.createClientData("client2")
      val userData1 = dataService.createUserData("user1").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }
      val userData2 = dataService.createUserData("user2").apply { lastAccess = LocalDateTime.now().minusMinutes(10) }

      clientData2.userData = userData2

      newTransaction()

      expirationService.findExpiredUsers(DateTimePeriod(minutes = 13)).shouldBeEmpty()
      expirationService.findExpiredUsers(DateTimePeriod(minutes = 9)).shouldContainExactly(userData1.id)
    }
  }
}
