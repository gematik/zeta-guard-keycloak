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

import de.gematik.zeta.zetaguard.keycloak.commons.events.zetaEvent
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession

/** Session-ending events whose sid must reach the enforcement points. */
private val SESSION_ENDED = setOf(EventType.LOGOUT, EventType.REVOKE_GRANT, EventType.USER_SESSION_DELETED)

private const val ADMIN_SESSION_PATH = "sessions/"

/**
 * Turns a session being ended on purpose into a block, so enforcement points learn about revocations no matter who initiated them — a client logging
 * out, a grant being revoked or an operator deleting a session in the admin API.
 *
 * Ending a session programmatically (`AuthenticationManager.backchannelLogout`, `UserSessionProvider.removeUserSession`) emits no event and never
 * reaches this listener; such callers, like the report endpoint, must record their block themselves.
 *
 * A session reaching the end of its own lifetime is not such a decision and produces no block: nobody withdrew trust ahead of schedule, and the
 * remaining exposure is bounded by the `exp` the enforcement points already check. Blocking on expiry too would make the stream scale with session
 * churn instead of with revocations.
 *
 * See META-INF/services/org.keycloak.events.EventListenerProviderFactory
 */
class RevocationEventListener(private val session: KeycloakSession) : EventListenerProvider {

  override fun onEvent(event: Event) {
    if (event.type !in SESSION_ENDED) return
    if (event.details?.get(Details.REASON) == Details.USER_SESSION_EXPIRED_REASON) return
    // ZETA events reuse these types to notify the user; whoever fires them revokes the affected sessions itself
    if (event.zetaEvent() != null) return

    blockSession(session, event.sessionId ?: return)
  }

  override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
    if (event.operationType != OperationType.DELETE || event.resourceType != ResourceType.USER_SESSION) return
    val path = event.resourcePath ?: return
    if (!path.startsWith(ADMIN_SESSION_PATH)) return

    blockSession(session, path.substringAfterLast("/"))
  }

  override fun close() {
    // No-op
  }
}
