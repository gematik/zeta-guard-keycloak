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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe

class UserDataStorageTest : AbstractUserDataTest() {
  init {

    test("basic persistence") {
      val clientData2 = dataService.createClientData("client2")
      val userData2 = dataService.createUserData("user2")
      clientData2.userData = userData2

      newTransaction()
      val clientData = dataService.findClientData(clientData2.id).shouldNotBeNull()
      clientData shouldBe clientData2
      clientData.attestationState shouldBe ClientAttestationState.PENDING
      clientData.userData shouldBe userData2
      clientData.clientAuthMethod shouldBe ClientAuthMethod.SMC_B
      clientData.registrationStatus.shouldBeNull()

      val userData = dataService.findUserData(userData2.id).shouldNotBeNull()
      userData shouldBe userData2
      userData.clients shouldBe listOf(clientData2)

      entityManager.remove(userData)
      dataService.findClientData(clientData2.id).shouldBeNull()
    }

    test("SEK_IDP client starts with EMAIL_CONFIRMATION_REQUIRED registration status") {
      val created = dataService.createClientData("mobile-client", ClientAuthMethod.SEK_IDP)

      newTransaction()
      val clientData = dataService.findClientData(created.id).shouldNotBeNull()
      clientData.clientAuthMethod shouldBe ClientAuthMethod.SEK_IDP
      clientData.registrationStatus shouldBe ClientRegistrationStatus.EMAIL_CONFIRMATION_REQUIRED
      clientData.attestationState shouldBe ClientAttestationState.PENDING
    }

    test("registrationStatus transitions persist across transactions") {
      val created = dataService.createClientData("mobile-client", ClientAuthMethod.SEK_IDP)

      newTransaction()
      val pending = dataService.findClientData(created.id).shouldNotBeNull()
      pending.registrationStatus = ClientRegistrationStatus.OTP_PENDING

      newTransaction()
      val confirmed = dataService.findClientData(created.id).shouldNotBeNull()
      confirmed.registrationStatus shouldBe ClientRegistrationStatus.OTP_PENDING
      confirmed.registrationStatus = ClientRegistrationStatus.CONFIRMED

      newTransaction()
      dataService.findClientData(created.id).shouldNotBeNull().registrationStatus shouldBe ClientRegistrationStatus.CONFIRMED
    }

    test("Client data deletion") {
      val clientData1 = dataService.createClientData("client1")
      val clientData2 = dataService.createClientData("client2")
      val userData2 = dataService.createUserData("user2")
      clientData2.userData = userData2
      clientData1.userData = userData2

      newTransaction()
      dataService.deleteClientData(clientData1.id)

      dataService.findClientData(clientData2.id).shouldNotBeNull()

      dataService.findUserData(userData2.id).shouldNotBeNull().clients shouldBe listOf(clientData2)
      dataService.findClientData(clientData1.id).shouldBeNull()
    }

    test("User data deletion cascades") {
      val clientData1 = dataService.createClientData("client1")
      val clientData2 = dataService.createClientData("client2")
      val userData2 = dataService.createUserData("user2")
      clientData2.userData = userData2
      clientData1.userData = userData2

      newTransaction()
      dataService.deleteUserData(userData2.id)

      dataService.findUserData(userData2.id).shouldBeNull()
      dataService.findClientData(clientData1.id).shouldBeNull()
      dataService.findClientData(clientData2.id).shouldBeNull()
    }
  }
}
