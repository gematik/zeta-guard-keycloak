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
package de.gematik.zeta.zetaguard.keycloak.commons.events

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import java.util.stream.Stream
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.EventStoreProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

private const val LISTENER_ID = "admin-log"

class ZetaAdminEventsTest :
  StringSpec({
    lateinit var events: MutableList<AdminEvent>
    lateinit var store: EventStoreProvider
    lateinit var session: KeycloakSession
    lateinit var realm: RealmModel

    beforeTest {
      events = mutableListOf()
      val listener =
          object : EventListenerProvider {
            override fun onEvent(event: Event) {}

            override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
              events += event
            }

            override fun close() {}
          }
      val factory =
          mockk<EventListenerProviderFactory> {
            every { id } returns LISTENER_ID
            every { isGlobal } returns false
          }
      realm =
          mockk {
            every { id } returns "realm-id"
            every { name } returns "zeta-guard"
            every { isAdminEventsEnabled } returns false
            every { eventsListenersStream } answers { Stream.of(LISTENER_ID) }
          }
      store = mockk(relaxed = true)
      session =
          mockk(relaxed = true) {
            every { keycloakSessionFactory.getProviderFactoriesStream(EventListenerProvider::class.java) } answers { Stream.of(factory) }
            every { getProvider(EventListenerProvider::class.java, LISTENER_ID) } returns listener
            every { getProvider(EventStoreProvider::class.java) } returns store
          }
    }

    fun log() =
        logZetaAdminEvent(
            session,
            realm,
            ZetaEvent.CLIENT_REMOVED,
            "clients/internal-lost-phone",
            ZetaActor("user-uuid", "internal-phone", "10.0.0.1"),
            mapOf(DETAIL_ZETA_TARGET_CLIENT_ID to "lost-phone"),
        )

    "a client management call reaches the realm's listeners as admin event, with the end user as actor" {
      log()

      val event = events.single()
      event.operationType shouldBe OperationType.DELETE
      event.resourceType shouldBe ResourceType.CLIENT
      event.resourcePath shouldBe "clients/internal-lost-phone"
      event.realmName shouldBe "zeta-guard"
      event.authDetails.userId shouldBe "user-uuid"
      event.authDetails.clientId shouldBe "internal-phone"
      event.authDetails.ipAddress shouldBe "10.0.0.1"
      event.details shouldContainExactly mapOf(DETAIL_ZETA_EVENT to "client_removed", DETAIL_ZETA_TARGET_CLIENT_ID to "lost-phone")
      verify(exactly = 0) { store.onEvent(any<AdminEvent>(), any()) }
    }

    "it is stored as well when the realm stores admin events" {
      every { realm.isAdminEventsEnabled } returns true

      log()

      verify { store.onEvent(events.single(), false) }
    }
  })
