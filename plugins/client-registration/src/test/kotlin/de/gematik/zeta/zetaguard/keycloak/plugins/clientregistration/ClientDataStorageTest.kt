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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import io.kotest.assertions.throwables.shouldThrow
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldContainExactlyInAnyOrder
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import org.hibernate.SessionFactory
import org.keycloak.models.jpa.entities.ClientEntity

class ClientDataStorageTest : AbstractUserDataTest() {
  init {
    beforeTest { entityManager.createQuery("DELETE FROM ClientEntity").executeUpdate() }

    test("SMC_B client is created with pending attestation and without registration status") {
      val created = dataService.createClientData("client1", ClientAuthMethod.SMC_B)

      newTransaction()
      val clientData = dataService.findClientData(created.id).shouldNotBeNull()
      clientData.clientAuthMethod shouldBe ClientAuthMethod.SMC_B
      clientData.attestationState shouldBe ClientAttestationState.PENDING
      clientData.registrationStatus.shouldBeNull()
      clientData.attestationType.shouldBeNull()
      clientData.userData.shouldBeNull()
      clientData.lastAccess shouldBe clientData.createdAt
    }

    test("unknown client data is not found") {
      dataService.findClientData("unknown").shouldBeNull()
    }

    test("only SEK_IDP clients with a Keycloak client are found") {
      dataService.createClientData("sekidp1", ClientAuthMethod.SEK_IDP)
      dataService.createClientData("sekidp2", ClientAuthMethod.SEK_IDP)
      dataService.createClientData("sekidp-without-keycloak-client", ClientAuthMethod.SEK_IDP)
      dataService.createClientData("smcb", ClientAuthMethod.SMC_B)

      entityManager.persist(keycloakClient("smcb").apply {
        redirectUris = setOf("http://smcb:8080") // Though this does not happen in production
      })
      entityManager.persist(keycloakClient("sekidp1").apply {
        redirectUris = setOf("http://sekidp1:8080")
      })
      entityManager.persist(keycloakClient("sekidp2").apply {
        redirectUris = setOf("http://sekidp1:8080", "http://sekidp2:8080")
      })

      newTransaction()
      dataService.findSekIdpRedirectUris(ZETA_REALM) shouldContainExactlyInAnyOrder listOf("http://sekidp1:8080", "http://sekidp2:8080")
      dataService.findSekIdpRedirectUris("jens").shouldBeEmpty()
    }

    test("with many clients the SEK_IDP redirect URIs are read with one statement and without loading clients") {
      repeat(500) {
        dataService.createClientData("smcb$it", ClientAuthMethod.SMC_B)
        entityManager.persist(keycloakClient("smcb$it").apply { redirectUris = setOf("http://smcb$it:8080") })
      }
      dataService.createClientData("sekidp1", ClientAuthMethod.SEK_IDP)
      entityManager.persist(keycloakClient("sekidp1").apply { redirectUris = setOf("http://sekidp1:8080") })

      newTransaction()
      val statistics = entityManager.entityManagerFactory.unwrap(SessionFactory::class.java).statistics
      statistics.isStatisticsEnabled = true
      statistics.clear()

      dataService.findSekIdpRedirectUris(ZETA_REALM) shouldContainExactlyInAnyOrder listOf("http://sekidp1:8080")

      statistics.prepareStatementCount shouldBe 1
      statistics.entityLoadCount shouldBe 0
    }

    test("no SEK_IDP clients are found if there are none") {
      dataService.createClientData("smcb", ClientAuthMethod.SMC_B)
      entityManager.persist(keycloakClient("smcb"))

      newTransaction()
      dataService.findSekIdpRedirectUris(ZETA_REALM).shouldBeEmpty()
    }

    test("deleteClientDataIfPresent tolerates a client that is already gone") {
      val created = dataService.createClientData("client1", ClientAuthMethod.SEK_IDP)

      newTransaction()
      dataService.deleteClientDataIfPresent(created.id) shouldBe true
      dataService.deleteClientDataIfPresent(created.id) shouldBe false
      dataService.findClientData(created.id).shouldBeNull()
    }

    test("deleteClientData fails for unknown client") {
      val ex = shouldThrow<IllegalStateException> { dataService.deleteClientData("unknown") }

      ex.message shouldContain "»unknown«"
    }
  }

  private fun keycloakClient(clientId: String) =
      ClientEntity().apply {
        id = "id-$clientId"
        this.clientId = clientId
        realmId = ZETA_REALM
      }
}
