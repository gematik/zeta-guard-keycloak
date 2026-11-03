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
import de.gematik.zeta.zetaguard.keycloak.commons.email.verifiedEmail
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.DETAIL_ZETA_TARGET_CLIENT_NAME
import de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaEvent
import de.gematik.zeta.zetaguard.keycloak.commons.events.zetaEvent
import org.jboss.logging.Logger
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerTransaction
import org.keycloak.events.admin.AdminEvent
import org.keycloak.models.KeycloakSession
import org.keycloak.models.utils.KeycloakModelUtils

private val logger: Logger = Logger.getLogger(NotificationEventListener::class.java)

/**
 * Sends the user notifications for ZETA events: N1 `client_added`, N3 `client_removed`, N5 `email_changed`. Keycloak's own events of
 * the same types are ignored.
 *
 * Like Keycloak's email event listener, the mails go out only once the transaction that fired the event has committed, in a transaction of their
 * own: a rolled back change notifies nobody. Without a verified address there is nobody to notify, e.g. for SMC-B identities.
 *
 * See META-INF/services/org.keycloak.events.EventListenerProviderFactory
 */
class NotificationEventListener(private val session: KeycloakSession) : EventListenerProvider {
  private val tx = EventListenerTransaction(null, ::notify)

  init {
    session.transactionManager.enlistAfterCompletion(tx)
  }

  override fun onEvent(event: Event) {
    if (event.zetaEvent() != null && event.realmId != null && event.userId != null) tx.addEvent(event)
  }

  override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
    // No-op
  }

  override fun close() {
    // No-op
  }

  private fun notify(event: Event) =
      KeycloakModelUtils.runJobInTransaction(session.keycloakSessionFactory) { jobSession ->
        val realm = jobSession.realms().getRealm(event.realmId) ?: return@runJobInTransaction
        jobSession.context.realm = realm
        val clientName = event.details?.get(DETAIL_ZETA_TARGET_CLIENT_NAME)

        val zetaEvent = event.zetaEvent()
        if (zetaEvent != null) {
          logger.debugf("notify »%s«, userId=»%s«", zetaEvent, event.userId)
        }

        when (zetaEvent) {
          ZetaEvent.EMAIL_CHANGED -> event.details?.get(Details.PREVIOUS_EMAIL)?.takeIf { it.isNotBlank() }
              ?.let { EmailChangeNotifier.notifyOldAddress(jobSession, it) }

          ZetaEvent.CLIENT_ADDED -> verifiedEmail(jobSession, event)?.let { ClientNotifier.notifyClientAdded(jobSession, it, clientName) }
          ZetaEvent.CLIENT_REMOVED -> verifiedEmail(jobSession, event)?.let { ClientNotifier.notifyClientRemoved(jobSession, it, clientName, event.removalReason()) }
          null -> Unit
        }
      }

  private fun Event.removalReason(): ClientRemovalReason? = details?.get(Details.REASON)?.let { reason -> ClientRemovalReason.entries.find { it.value == reason } }

  private fun verifiedEmail(jobSession: KeycloakSession, event: Event): String? =
      jobSession.users().getUserById(jobSession.context.realm, event.userId)?.verifiedEmail().also {
        if (it == null) logger.debugf("No verified address for user »%s«, not sending »%s«", event.userId, event.zetaEvent()?.message)
      }
}
