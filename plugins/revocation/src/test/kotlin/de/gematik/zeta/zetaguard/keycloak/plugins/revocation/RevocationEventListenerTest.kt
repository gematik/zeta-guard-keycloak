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
package de.gematik.zeta.zetaguard.keycloak.plugins.revocation

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.collections.shouldBeEmpty
import io.kotest.matchers.collections.shouldHaveSize
import io.kotest.matchers.longs.shouldBeBetween
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

private const val SID = "mzEPAZMnxCwiDaN8D7DVDi91"
private const val BLOCK_TTL_SECONDS = 60 * 60L

/**
 * Which events become blocks, and how far the block reaches. The store itself is a fake: what matters here is the decision and the bound, both of
 * which the listener derives on its own — the merge rules have their own test.
 */
class RevocationEventListenerTest :
    StringSpec({
      lateinit var blocked: MutableList<Block>

      val store =
          object : BlockStore {
            override fun put(block: Block) {
              blocked += block
            }

            override fun snapshot(): List<Block> = blocked.toList()

            override fun subscribe(onBlock: (Block) -> Unit) = AutoCloseable {}

            override fun probe() {}
          }

      val realm = mockk<RealmModel> { every { accessTokenLifespan } returns 300 }
      val session = mockk<KeycloakSession> { every { context } returns mockk<KeycloakContext> { every { this@mockk.realm } returns realm } }
      val listener = RevocationEventListener(session)

      beforeSpec {
        mockkObject(BlockStore)
        every { BlockStore.of(any()) } returns store
      }

      afterSpec { unmockkObject(BlockStore) }

      beforeTest { blocked = mutableListOf() }

      fun event(type: EventType, sid: String? = SID, details: Map<String, String>? = null) =
          Event().apply {
            this.type = type
            this.sessionId = sid
            details?.let { this.details = it }
          }

      fun adminEvent(
          operation: OperationType = OperationType.DELETE,
          resource: ResourceType = ResourceType.USER_SESSION,
          path: String? = "sessions/$SID",
      ) =
          AdminEvent().apply {
            operationType = operation
            resourceType = resource
            resourcePath = path
          }

      "blocks a logout for the flat block ttl, not the realm access token lifespan" {
        val now = System.currentTimeMillis() / 1000

        listener.onEvent(event(EventType.LOGOUT))

        blocked shouldHaveSize 1
        blocked[0].what shouldBe SID
        // Neither the session nor the token's OPA-granted TTL is knowable here, so the bound is flat — notably NOT the realm's 300s.
        blocked[0].until.shouldBeBetween(now + BLOCK_TTL_SECONDS, now + BLOCK_TTL_SECONDS + 5)
        blocked[0].`when`.shouldBeBetween(now, now + 5)
      }

      "blocks a revoked grant" {
        listener.onEvent(event(EventType.REVOKE_GRANT))

        blocked.map { it.what } shouldBe listOf(SID)
      }

      "blocks a session deleted through the admin API" {
        listener.onEvent(event(EventType.USER_SESSION_DELETED))

        blocked.map { it.what } shouldBe listOf(SID)
      }

      "does not block a session that merely expired" {
        listener.onEvent(event(EventType.USER_SESSION_DELETED, details = mapOf(Details.REASON to Details.USER_SESSION_EXPIRED_REASON)))

        // Nobody withdrew trust ahead of schedule, so there is nothing to tell the enforcement points about.
        blocked.shouldBeEmpty()
      }

      "ignores events that do not end a session" {
        listener.onEvent(event(EventType.LOGIN))
        listener.onEvent(event(EventType.REFRESH_TOKEN))
        listener.onEvent(event(EventType.CODE_TO_TOKEN))

        blocked.shouldBeEmpty()
      }

      "ignores a session-ending event without a sid" {
        listener.onEvent(event(EventType.LOGOUT, sid = null))
        listener.onEvent(event(EventType.LOGOUT, sid = ""))

        blocked.shouldBeEmpty()
      }

      "blocks the sid an admin deleted" {
        listener.onEvent(adminEvent(), false)

        blocked.map { it.what } shouldBe listOf(SID)
      }

      "ignores admin events about anything else" {
        listener.onEvent(adminEvent(operation = OperationType.CREATE), false)
        listener.onEvent(adminEvent(resource = ResourceType.CLIENT), false)
        listener.onEvent(adminEvent(path = "realms/zeta-guard"), false)
        listener.onEvent(adminEvent(path = null), false)

        blocked.shouldBeEmpty()
      }
    })
