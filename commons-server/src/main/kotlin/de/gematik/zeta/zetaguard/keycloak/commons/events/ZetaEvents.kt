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

import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventBuilder
import org.keycloak.events.EventType
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

/** Marks an event as fired by ZETA Guard; the value is the [ZetaEvent.message]. */
const val DETAIL_ZETA_EVENT = "zeta_event"

/** The client the event is about, e.g. the removed device; not necessarily the client that triggered it. */
const val DETAIL_ZETA_TARGET_CLIENT_ID = "zeta_target_client_id"

/** Display name of the target client, if it has one. */
const val DETAIL_ZETA_TARGET_CLIENT_NAME = "zeta_target_client_name"

/**
 * Client management events that notify the affected user, carried by a standard Keycloak event type so the regular
 * event infrastructure (store, listeners) applies. [adminOperation] and [adminResource] describe the call as admin event (see [logZetaAdminEvent]).
 */
enum class ZetaEvent(val type: EventType, val message: String, val adminOperation: OperationType, val adminResource: ResourceType) {
  /** N1: a client was registered to an existing identity. */
  CLIENT_ADDED(EventType.CLIENT_REGISTER, "client_added", OperationType.CREATE, ResourceType.CLIENT),

  /** N3: a client was removed, by the user or by ZETA Guard; see [ClientRemovalReason]. */
  CLIENT_REMOVED(EventType.REVOKE_GRANT, "client_removed", OperationType.DELETE, ResourceType.CLIENT),

  /** N5: the identity's email address was changed; [Details.PREVIOUS_EMAIL] holds the address to notify. */
  EMAIL_CHANGED(EventType.UPDATE_EMAIL, "email_changed", OperationType.UPDATE, ResourceType.USER),
}

/** Why a client was removed, in [Details.REASON] of a [ZetaEvent.CLIENT_REMOVED]. */
enum class ClientRemovalReason(val value: String) {
  USER_REQUEST("user_request"),
  EXPIRED("expired"),
  MAX_CLIENTS_EXCEEDED("max_clients_exceeded"),
  EMAIL_CHANGE_PENDING("email_change_pending"),
}

/** The ZETA event this event carries, or null for any other event, including Keycloak's own events of the same types. */
fun Event.zetaEvent(): ZetaEvent? = details?.get(DETAIL_ZETA_EVENT)?.let { message -> ZetaEvent.entries.find { it.message == message } }

/**
 * Fire [event] for the Keycloak user [userId] (the internal id, not the username).
 *
 * Deliberately without a session id: listeners that act on the session of an event, like the revocation listener on [EventType.REVOKE_GRANT], must
 * not mistake the identity's own session for the affected one.
 */
fun fireZetaEvent(
    session: KeycloakSession,
    realm: RealmModel,
    event: ZetaEvent,
    userId: String,
    targetClientId: String? = null,
    targetClientName: String? = null,
    details: Map<String, String> = emptyMap(),
) {
  // EventBuilder.detail skips null and blank values
  val builder =
      EventBuilder(realm, session)
          .event(event.type)
          .user(userId)
          .detail(DETAIL_ZETA_EVENT, event.message)
          .detail(DETAIL_ZETA_TARGET_CLIENT_ID, targetClientId)
          .detail(DETAIL_ZETA_TARGET_CLIENT_NAME, targetClientName)

  details.forEach { (key, value) -> builder.detail(key, value) }
  builder.success()
}

/** Fire [ZetaEvent.CLIENT_REMOVED]; see [fireZetaEvent]. */
fun fireClientRemoved(
    session: KeycloakSession,
    realm: RealmModel,
    userId: String,
    clientId: String,
    clientName: String?,
    reason: ClientRemovalReason,
) = fireZetaEvent(session, realm, ZetaEvent.CLIENT_REMOVED, userId, clientId, clientName, mapOf(Details.REASON to reason.value))
