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
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.maps.shouldContainExactly
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import java.util.stream.Stream
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.tracing.TracingProvider

private const val LISTENER_ID = "capture"

class ZetaEventsTest :
  StringSpec({
    lateinit var events: MutableList<Event>
    lateinit var session: KeycloakSession

    val realm =
        mockk<RealmModel> {
          every { id } returns "realm-id"
          every { name } returns "zeta-guard"
          every { isEventsEnabled } returns false
          every { eventsListenersStream } answers { Stream.of(LISTENER_ID) }
          every { enabledEventTypesStream } answers { Stream.empty() }
        }

    beforeTest {
      events = mutableListOf()
      val listener =
          object : EventListenerProvider {
            override fun onEvent(event: Event) {
              events += event
            }

            override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {}

            override fun close() {}
          }
      val factory =
          mockk<EventListenerProviderFactory> {
            every { id } returns LISTENER_ID
            every { isGlobal } returns false
          }
      session =
          mockk(relaxed = true) {
            every { keycloakSessionFactory.getProviderFactoriesStream(EventListenerProvider::class.java) } answers { Stream.of(factory) }
            every { getProvider(EventListenerProvider::class.java, LISTENER_ID) } returns listener
            every { getProvider(TracingProvider::class.java) } returns mockk(relaxed = true)
          }
    }

    "a client removal is a REVOKE_GRANT of the identity, marked as ZETA event, without a session" {
      fireClientRemoved(session, realm, "user-uuid", "lost-phone", "Old phone", ClientRemovalReason.USER_REQUEST)

      events shouldHaveSize 1
      val event = events.single()
      event.type shouldBe EventType.REVOKE_GRANT
      event.userId shouldBe "user-uuid"
      event.sessionId.shouldBeNull()
      event.zetaEvent() shouldBe ZetaEvent.CLIENT_REMOVED
      event.details shouldContainExactly
          mapOf(
              DETAIL_ZETA_EVENT to "client_removed",
              DETAIL_ZETA_TARGET_CLIENT_ID to "lost-phone",
              DETAIL_ZETA_TARGET_CLIENT_NAME to "Old phone",
              Details.REASON to "user_request",
          )
    }

    "an email change carries the previous address and no target client" {
      fireZetaEvent(session, realm, ZetaEvent.EMAIL_CHANGED, "user-uuid", details = mapOf(Details.PREVIOUS_EMAIL to "old@example.de"))

      val event = events.single()
      event.type shouldBe EventType.UPDATE_EMAIL
      event.details shouldContainExactly mapOf(DETAIL_ZETA_EVENT to "email_changed", Details.PREVIOUS_EMAIL to "old@example.de")
    }

    "Keycloak's own events of the same types are no ZETA events" {
      Event().apply { type = EventType.UPDATE_EMAIL }.zetaEvent().shouldBeNull()
      Event().apply { details = mapOf(DETAIL_ZETA_EVENT to "unknown") }.zetaEvent().shouldBeNull()
    }
  })
