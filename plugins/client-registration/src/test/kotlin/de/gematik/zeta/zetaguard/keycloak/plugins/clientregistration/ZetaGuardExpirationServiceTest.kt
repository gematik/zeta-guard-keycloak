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

import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import io.mockk.verifyOrder
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.jpa.JpaRealmProvider
import org.keycloak.models.jpa.JpaUserProvider

private const val ZETA_EVENTS = "de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEventsKt"
private const val USER_NAME = "spicy-hash-of-kvnr"
private const val USER_ID = "user-uuid"
private const val CLIENT_ID = "old-phone"

/** Removals by ZETA Guard notify the owner like a removal by the user does (N3 `client_removed`). */
class ZetaGuardExpirationServiceTest :
  StringSpec({
    lateinit var realm: RealmModel
    lateinit var session: KeycloakSession

    beforeTest {
      realm =
          mockk(relaxed = true) {
            // internal id and client_id differ, so mixing them up shows
            every { getClientByClientId(CLIENT_ID) } returns
                mockk<ClientModel> {
                  every { id } returns "internal-$CLIENT_ID"
                  every { name } returns "Old phone"
                }
          }
      val user = mockk<UserModel> { every { id } returns USER_ID }
      session =
          mockk(relaxed = true) {
            every { realms().getRealmByName(ZETA_REALM) } returns realm
            // like the expiration job's session, which is bound to no realm
            every { users() } throws IllegalArgumentException("Session not bound to a realm")
            every { getProvider(JpaConnectionProvider::class.java) } returns mockk(relaxed = true)
          }

      mockkConstructor(ZetaGuardDataService::class, ZetaGuardClientExpirationDao::class, JpaRealmProvider::class, JpaUserProvider::class)
      every { anyConstructed<JpaUserProvider>().getUserByUsername(realm, USER_NAME) } returns user
      every { anyConstructed<ZetaGuardDataService>().findClientOwner(CLIENT_ID) } returns USER_NAME
      every { anyConstructed<ZetaGuardDataService>().deleteClientDataIfPresent(CLIENT_ID) } returns true
      every { anyConstructed<JpaRealmProvider>().removeClient(realm, "internal-$CLIENT_ID") } returns true
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClientRegistrations(any()) } returns emptyList()
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClients(any()) } returns emptyList()
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredUsers(any()) } returns emptyList()

      mockkObject(SecurityEventLogger)
      mockkStatic(ZETA_EVENTS)
      justRun { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
    }

    afterTest { unmockkAll() }

    "evicting the oldest client notifies its owner with reason max_clients_exceeded" {
      every { anyConstructed<ZetaGuardClientExpirationDao>().findOldestClients(USER_NAME) } returns listOf(CLIENT_ID)

      ZetaGuardExpirationService(session).removeOldestClient(USER_NAME) shouldBe true

      verifyOrder {
        anyConstructed<ZetaGuardDataService>().findClientOwner(CLIENT_ID)
        anyConstructed<ZetaGuardDataService>().deleteClientDataIfPresent(CLIENT_ID)
        fireClientRemoved(session, realm, USER_ID, CLIENT_ID, "Old phone", ClientRemovalReason.MAX_CLIENTS_EXCEEDED)
      }
      verify(exactly = 1) { SecurityEventLogger.logClientDeleted(CLIENT_ID, "max_clients_exceeded") }
    }

    "an expired client notifies its owner with reason expired" {
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClients(any()) } returns listOf(CLIENT_ID)

      ZetaGuardExpirationService(session).runExpiration() shouldBe (1 to 0)

      verify { fireClientRemoved(session, realm, USER_ID, CLIENT_ID, "Old phone", ClientRemovalReason.EXPIRED) }
      verify { SecurityEventLogger.logClientDeleted(CLIENT_ID, "expired") }
      verify { anyConstructed<JpaRealmProvider>().removeClient(realm, "internal-$CLIENT_ID") }
    }

    "the ZETA data of a client whose Keycloak client is already gone is still deleted" {
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClients(any()) } returns listOf(CLIENT_ID)
      every { realm.getClientByClientId(CLIENT_ID) } returns null

      ZetaGuardExpirationService(session).runExpiration() shouldBe (0 to 0)

      verify { anyConstructed<ZetaGuardDataService>().deleteClientDataIfPresent(CLIENT_ID) }
      verify { SecurityEventLogger.logClientDeleted(CLIENT_ID, "expired") }
      verify { fireClientRemoved(session, realm, USER_ID, CLIENT_ID, null, ClientRemovalReason.EXPIRED) }
      verify(exactly = 0) { anyConstructed<JpaRealmProvider>().removeClient(any(), any()) }
    }

    "a client removed concurrently by someone else notifies nobody" {
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClients(any()) } returns listOf(CLIENT_ID)
      every { anyConstructed<ZetaGuardDataService>().deleteClientDataIfPresent(CLIENT_ID) } returns false

      ZetaGuardExpirationService(session).runExpiration() shouldBe (0 to 0)

      verify(exactly = 0) { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      verify(exactly = 0) { SecurityEventLogger.logClientDeleted(any(), any()) }
    }

    "a client without owner notifies nobody, but its deletion is still a security event" {
      every { anyConstructed<ZetaGuardClientExpirationDao>().findExpiredClients(any()) } returns listOf(CLIENT_ID)
      every { anyConstructed<ZetaGuardDataService>().findClientOwner(CLIENT_ID) } returns null

      ZetaGuardExpirationService(session).runExpiration() shouldBe (1 to 0)

      verify(exactly = 0) { fireClientRemoved(any(), any(), any(), any(), any(), any()) }
      verify { SecurityEventLogger.logClientDeleted(CLIENT_ID, "expired") }
    }
  })
