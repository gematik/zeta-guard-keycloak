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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientmanagement.notifications

import de.gematik.zeta.zetaguard.keycloak.commons.email.ClientNotifier
import de.gematik.zeta.zetaguard.keycloak.commons.email.EmailChangeNotifier
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_EVENT
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_TARGET_CLIENT_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import io.kotest.core.spec.style.StringSpec
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mockk.verify
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionTask
import org.keycloak.models.KeycloakTransaction
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.utils.KeycloakModelUtils

private const val REALM_ID = "realm-id"
private const val USER_ID = "user-uuid"
private const val EMAIL = "kvnr-user@example.de"

/** Which events notify whom, and that nothing is sent before the triggering transaction committed. */
class NotificationEventListenerTest :
  StringSpec({
    lateinit var afterCompletion: MutableList<KeycloakTransaction>
    lateinit var user: UserModel
    lateinit var jobSession: KeycloakSession
    lateinit var listener: NotificationEventListener

    fun event(zetaEvent: ZetaEvent?, vararg details: Pair<String, String>) =
        Event().apply {
          type = zetaEvent?.type ?: EventType.UPDATE_EMAIL
          realmId = REALM_ID
          userId = USER_ID
          this.details = (zetaEvent?.let { mapOf(DETAIL_ZETA_EVENT to it.message) }.orEmpty() + details)
        }

    fun commit() = afterCompletion.forEach {
      it.begin()
      it.commit()
    }

    fun rollback() = afterCompletion.forEach {
      it.begin()
      it.rollback()
    }

    beforeTest {
      afterCompletion = mutableListOf()
      user =
          mockk<UserModel> {
            every { email } returns EMAIL
            every { isEmailVerified } returns true
          }
      val realm = mockk<RealmModel>()
      jobSession =
          mockk(relaxed = true) {
            every { realms().getRealm(REALM_ID) } returns realm
            every { users().getUserById(any(), USER_ID) } answers { user }
          }
      val session =
          mockk<KeycloakSession>(relaxed = true) {
            every { transactionManager.enlistAfterCompletion(any()) } answers { afterCompletion += firstArg<KeycloakTransaction>() }
          }

      mockkStatic(KeycloakModelUtils::class)
      every { KeycloakModelUtils.runJobInTransaction(any(), any<KeycloakSessionTask>()) } answers { secondArg<KeycloakSessionTask>().run(jobSession) }
      mockkObject(ClientNotifier, EmailChangeNotifier)
      justRun { ClientNotifier.notifyClientAdded(any(), any(), any()) }
      justRun { ClientNotifier.notifyClientRemoved(any(), any(), any(), any()) }
      justRun { EmailChangeNotifier.notifyOldAddress(any(), any()) }

      listener = NotificationEventListener(session)
    }

    afterTest { unmockkAll() }

    "a removed client notifies the identity's verified address (N3), once the transaction committed" {
      listener.onEvent(event(ZetaEvent.CLIENT_REMOVED, DETAIL_ZETA_TARGET_CLIENT_NAME to "Old phone", Details.REASON to "max_clients_exceeded"))

      verify(exactly = 0) { ClientNotifier.notifyClientRemoved(any(), any(), any(), any()) }

      commit()

      verify { ClientNotifier.notifyClientRemoved(jobSession, EMAIL, "Old phone", ClientRemovalReason.MAX_CLIENTS_EXCEEDED) }
    }

    "an added client notifies the identity's verified address (N1)" {
      listener.onEvent(event(ZetaEvent.CLIENT_ADDED, DETAIL_ZETA_TARGET_CLIENT_NAME to "New phone"))
      commit()

      verify { ClientNotifier.notifyClientAdded(jobSession, EMAIL, "New phone") }
    }

    "an email change notifies the previous address, not the current one (N5)" {
      listener.onEvent(event(ZetaEvent.EMAIL_CHANGED, Details.PREVIOUS_EMAIL to "old@example.de"))
      commit()

      verify { EmailChangeNotifier.notifyOldAddress(jobSession, "old@example.de") }
    }

    "a rolled back change notifies nobody" {
      listener.onEvent(event(ZetaEvent.CLIENT_REMOVED))
      rollback()

      verify(exactly = 0) { ClientNotifier.notifyClientRemoved(any(), any(), any(), any()) }
    }

    "an identity without a verified address gets nothing" {
      every { user.isEmailVerified } returns false

      listener.onEvent(event(ZetaEvent.CLIENT_REMOVED))
      commit()

      verify(exactly = 0) { ClientNotifier.notifyClientRemoved(any(), any(), any(), any()) }
    }

    "Keycloak's own events of the same types are ignored" {
      listener.onEvent(event(null, Details.PREVIOUS_EMAIL to "old@example.de"))
      commit()

      verify(exactly = 0) { EmailChangeNotifier.notifyOldAddress(any(), any()) }
    }
  })
