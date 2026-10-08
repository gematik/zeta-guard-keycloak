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

import org.jboss.logging.Logger
import org.keycloak.events.Details
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.EventType
import org.keycloak.events.admin.AdminEvent
import org.keycloak.events.admin.OperationType
import org.keycloak.events.admin.ResourceType
import org.keycloak.models.KeycloakSession

private val log = Logger.getLogger(RevocationEventListener::class.java)

/** Session-ending events whose sid must reach the enforcement points. */
private val SESSION_ENDED = setOf(EventType.LOGOUT, EventType.REVOKE_GRANT, EventType.USER_SESSION_DELETED)

private const val ADMIN_SESSION_PATH = "sessions/"

/**
 * How long a block is held for sessions ended through Keycloak — see [RevocationEventListener.block] for why it is a flat value rather than the
 * token's own lifetime. Assumes no OPA policy ever grants an `access_ttl` beyond this; a longer one would leave the tail of that token unblocked.
 */
private const val BLOCK_TTL_SECONDS = 60 * 60L

/**
 * Turns a session being ended on purpose into a block, so enforcement points learn about revocations no matter who initiated them — a client logging
 * out, a grant being revoked, an operator deleting a session in the admin API, or our own report endpoint (which ends the session through Keycloak
 * and therefore lands here too).
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
    block(event.sessionId ?: return)
  }

  override fun onEvent(event: AdminEvent, includeRepresentation: Boolean) {
    if (event.operationType != OperationType.DELETE || event.resourceType != ResourceType.USER_SESSION) return
    val path = event.resourcePath ?: return
    if (!path.startsWith(ADMIN_SESSION_PATH)) return
    block(path.substringAfterLast("/"))
  }

  override fun close() {
    // No-op
  }

  /**
   * The session is gone by now, so its lifetime cannot bound the block — and neither can the token's, which is what actually matters: the access
   * token TTL is decided per exchange by OPA (`access_ttl`) and kept in the session note that dies with the session, so it is not knowable here.
   * Asking OPA would answer "what would a new exchange get", not "what did the issued token get".
   *
   * So block for a flat [BLOCK_TTL_SECONDS], comfortably longer than any access token lifetime the policy is expected to grant. The asymmetry
   * justifies it: over-blocking costs one cache entry outliving its purpose (the session is dead and sids are not reused), while under-blocking would
   * let a revoked session's token keep working until its own `exp` — exactly what this is supposed to prevent.
   */
  private fun block(sid: String) {
    if (sid.isBlank()) return
    val now = System.currentTimeMillis() / 1000
    val block = Block(`when` = now, until = now + BLOCK_TTL_SECONDS, what = sid)
    runCatching { BlockStore.of(session).put(block) }
        .onFailure { log.warnf(it, "could not record block for session %s", sid) }
        .onSuccess { log.debugf("recorded block for session %s until %d", sid, block.until) }
  }
}
