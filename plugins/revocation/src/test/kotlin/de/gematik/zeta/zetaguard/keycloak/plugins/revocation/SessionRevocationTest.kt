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
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import io.mockk.MockKMatcherScope
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakTransaction
import org.keycloak.models.KeycloakTransactionManager
import org.keycloak.models.RealmModel
import org.keycloak.models.UserSessionModel
import org.keycloak.models.UserSessionProvider
import org.keycloak.services.managers.AuthenticationManager

class SessionRevocationTest :
    StringSpec({
      lateinit var blocked: MutableList<Block>
      lateinit var afterCompletion: MutableList<KeycloakTransaction>
      lateinit var sessions: UserSessionProvider
      lateinit var session: KeycloakSession

      val realm = mockk<RealmModel>()
      val client = mockk<ClientModel>()

      fun userSession(id: String) = mockk<UserSessionModel> { every { this@mockk.id } returns id }

      /** Online sessions of [client] are found by client and by id; offline ones likewise, sharing the id of their online counterpart. */
      fun given(online: List<UserSessionModel> = emptyList(), offline: List<UserSessionModel> = emptyList()) {
        every { sessions.readOnlyStreamUserSessions(realm, client, -1, -1) } answers { online.stream() }
        every { sessions.readOnlyStreamOfflineUserSessions(realm, client, -1, -1) } answers { offline.stream() }
        every { sessions.getUserSession(realm, any()) } answers { online.find { it.id == secondArg() } }
        every { sessions.getOfflineUserSession(realm, any()) } answers { offline.find { it.id == secondArg() } }
      }

      fun MockKMatcherScope.logout(userSession: UserSessionModel, offline: Boolean) =
          AuthenticationManager.backchannelLogout(session, realm, userSession, any(), any(), any(), true, offline)

      /** What Keycloak's transaction manager does with the after-completion transactions once the main ones committed, or rolled back. */
      fun commit() = afterCompletion.forEach {
        it.begin()
        it.commit()
      }

      fun rollback() = afterCompletion.forEach {
        it.begin()
        it.rollback()
      }

      beforeTest {
        blocked = mutableListOf()
        afterCompletion = mutableListOf()
        val store =
            object : BlockStore {
              override fun put(block: Block) {
                blocked += block
              }

              override fun snapshot(): List<Block> = blocked.toList()

              override fun subscribe(onBlock: (Block) -> Unit) = AutoCloseable {}

              override fun probe() {}
            }
        mockkObject(BlockStore)
        every { BlockStore.of(any()) } returns store

        mockkStatic(AuthenticationManager::class)
        every { AuthenticationManager.backchannelLogout(any(), any(), any(), any(), any(), any(), any(), any()) } returns mockk()

        val transactionManager = mockk<KeycloakTransactionManager> { every { enlistAfterCompletion(any()) } answers { afterCompletion += firstArg<KeycloakTransaction>() } }
        sessions = mockk()
        session =
            mockk(relaxed = true) {
              every { sessions() } returns sessions
              every { this@mockk.transactionManager } returns transactionManager
            }
      }

      afterTest { unmockkAll() }

      "ends every online session of the client right away and blocks it once the transaction committed" {
        val first = userSession("sid-1")
        val second = userSession("sid-2")
        given(online = listOf(first, second))

        revokeClientSessions(session, realm, client) shouldContainExactly listOf("sid-1", "sid-2")

        verify { logout(first, offline = false) }
        verify { logout(second, offline = false) }
        blocked.shouldBeEmpty()

        commit()

        blocked.map { it.what } shouldContainExactly listOf("sid-1", "sid-2")
      }

      "a rolled back transaction blocks nothing" {
        given(online = listOf(userSession("sid-1")))

        revokeClientSessions(session, realm, client)
        rollback()

        blocked.shouldBeEmpty()
      }

      "an offline session is ended as offline session, which also covers its online counterpart" {
        val online = userSession("sid-1")
        val offline = userSession("sid-1")
        given(online = listOf(online), offline = listOf(offline))

        revokeClientSessions(session, realm, client) shouldContainExactly listOf("sid-1")
        commit()

        blocked.map { it.what } shouldContainExactly listOf("sid-1")
        verify(exactly = 1) { logout(offline, offline = true) }
        verify(exactly = 0) { logout(online, offline = false) }
      }

      "an offline session without online counterpart is revoked too" {
        val offline = userSession("sid-offline")
        given(offline = listOf(offline))

        revokeClientSessions(session, realm, client) shouldContainExactly listOf("sid-offline")

        verify { logout(offline, offline = true) }
      }

      "a client without sessions revokes nothing" {
        given()

        revokeClientSessions(session, realm, client).shouldBeEmpty()

        afterCompletion.shouldBeEmpty()
        verify(exactly = 0) { AuthenticationManager.backchannelLogout(any(), any(), any(), any(), any(), any(), any(), any()) }
      }

      "a failing block store neither prevents ending the session nor fails the commit" {
        val only = userSession("sid-1")
        given(online = listOf(only))
        every { BlockStore.of(any()) } throws IllegalStateException("ISPN000436")

        revokeClientSessions(session, realm, client) shouldBe listOf("sid-1")
        commit()

        verify { logout(only, offline = false) }
      }

      "ending an unknown session does nothing" {
        given()

        endSession(session, realm, "gone") shouldBe false

        verify(exactly = 0) { AuthenticationManager.backchannelLogout(any(), any(), any(), any(), any(), any(), any(), any()) }
      }
    })
