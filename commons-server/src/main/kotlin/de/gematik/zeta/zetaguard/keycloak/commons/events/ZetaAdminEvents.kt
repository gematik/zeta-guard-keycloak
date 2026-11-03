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

import java.util.UUID
import org.jboss.logging.Logger
import org.keycloak.common.util.Time
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.events.EventStoreProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.AuthDetails
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

private val logger: Logger = Logger.getLogger("de.gematik.zeta.zetaguard.keycloak.commons.events.ZetaAdminEvents")

/** The identity's ZETA user data id (its Keycloak username); identifies the identity even when its Keycloak user is gone. */
const val DETAIL_ZETA_USER = "zeta_user"

/**
 * Who triggered a [ZetaEvent]: the identity's user and the calling client (Keycloak internal ids, as in the admin API's [AuthDetails]). The user
 * is null if the identity has no Keycloak user (any more); see [DETAIL_ZETA_USER].
 *
 * Unlike an [AdminEvent] of the admin API, the actor is the end user, authenticated by the PEP.
 */
data class ZetaActor(val userId: String?, val clientId: String?, val ipAddress: String? = null)

/**
 * Log a client management call as [AdminEvent] (A_<tas>008), like Keycloak's AdminEventBuilder: to the event store if admin events are enabled, and
 * to the realm's event listeners, among them the admin event log of the PDP database.
 *
 * Keycloak's AdminEventBuilder needs an admin login, so the event is built here; it is marked with [DETAIL_ZETA_EVENT] like the user event.
 */
fun logZetaAdminEvent(
    session: KeycloakSession,
    realm: RealmModel,
    event: ZetaEvent,
    resourcePath: String,
    actor: ZetaActor,
    details: Map<String, String> = emptyMap(),
) {
  val authDetails = AuthDetails()
  authDetails.realmId = realm.id
  authDetails.realmName = realm.name
  authDetails.userId = actor.userId
  authDetails.clientId = actor.clientId
  authDetails.ipAddress = actor.ipAddress

  val adminEvent = AdminEvent()
  adminEvent.id = UUID.randomUUID().toString()
  adminEvent.time = Time.currentTimeMillis()
  adminEvent.realmId = realm.id
  adminEvent.realmName = realm.name
  adminEvent.authDetails = authDetails
  adminEvent.operationType = event.adminOperation
  adminEvent.resourceType = event.adminResource
  adminEvent.resourcePath = resourcePath
  adminEvent.details = mapOf(DETAIL_ZETA_EVENT to event.message) + details.filterValues { it.isNotBlank() }

  if (realm.isAdminEventsEnabled) {
    session.getProvider(EventStoreProvider::class.java)?.onEvent(adminEvent, false)
  }

  val listenerIds = realm.eventsListenersStream.toList().toSet()
  session.keycloakSessionFactory
      .getProviderFactoriesStream(EventListenerProvider::class.java)
      .filter { it.id in listenerIds || (it as EventListenerProviderFactory).isGlobal }
      .forEach { factory ->
        runCatching { session.getProvider(EventListenerProvider::class.java, factory.id).onEvent(adminEvent, false) }
            .onFailure { logger.errorf(it, "Failed to send admin event »%s« to listener »%s«", event.message, factory.id) }
      }
}
