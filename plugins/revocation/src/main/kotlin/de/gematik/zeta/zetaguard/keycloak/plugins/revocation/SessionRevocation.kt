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

import arrow.core.Either
import org.jboss.logging.Logger
import org.keycloak.models.AbstractKeycloakTransaction
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.services.managers.AuthenticationManager

private val log = Logger.getLogger("de.gematik.zeta.zetaguard.keycloak.plugins.revocation.SessionRevocation")

/**
 * How long a block is held for sessions ended through Keycloak — see [blockSession] for why it is a flat value rather than the token's own lifetime.
 * Assumes no OPA policy ever grants an `access_ttl` beyond this; a longer one would leave the tail of that token unblocked.
 */
private const val BLOCK_TTL_SECONDS = 60 * 60L

/**
 * Block [sid] for the enforcement points.
 *
 * The session is gone by now (or about to be), so its lifetime cannot bound the block — and neither can the token's, which is what actually matters:
 * the access token TTL is decided per exchange by OPA (`access_ttl`) and kept in the session note that dies with the session, so it is not knowable
 * here. Asking OPA would answer "what would a new exchange get", not "what did the issued token get".
 *
 * So block for a flat [BLOCK_TTL_SECONDS], comfortably longer than any access token lifetime the policy is expected to grant. The asymmetry justifies
 * it: over-blocking costs one cache entry outliving its purpose (the session is dead and sids are not reused), while under-blocking would let a
 * revoked session's token keep working until its own `exp` — exactly what this is supposed to prevent.
 *
 * @return false if the block could not be recorded; the failure is logged, not thrown
 */
fun blockSession(session: KeycloakSession, sid: String): Boolean {
  if (sid.isBlank()) return false
  val now = System.currentTimeMillis() / 1000
  val block = Block(`when` = now, until = now + BLOCK_TTL_SECONDS, what = sid)

  return Either.catch { BlockStore.of(session).put(block) }
      .onLeft { log.warnf(it, "could not record block for session »%s«", sid) }
      .onRight { log.debugf("recorded block for session »%s« until »%d«", sid, block.until) }
      .isRight()
}

/**
 * End the user session [sid], online and offline: the offline session shares the online session's id (and so the `sid` of its tokens), but outlives
 * an online logout and could keep refreshing long after any block expired. Logging out the offline session also removes its online counterpart.
 *
 * Emits no event (see [RevocationEventListener]); callers record their block themselves.
 *
 * @return false if there is no such session
 */
internal fun endSession(session: KeycloakSession, realm: RealmModel, sid: String): Boolean {
  val sessions = session.sessions()
  val offline = sessions.getOfflineUserSession(realm, sid)
  val userSession = offline ?: sessions.getUserSession(realm, sid) ?: return false

  AuthenticationManager.backchannelLogout(
      session,
      realm,
      userSession,
      session.context.uri,
      session.context.connection,
      session.context.requestHeaders,
      true,
      offline != null,
  )
  return true
}

/**
 * Revoke every user session [client] takes part in, online or offline, e.g. before deleting the client of a lost device: each session is ended (see
 * [endSession]) and blocked for the enforcement points.
 *
 * Ending the sessions is part of the caller's transaction; the blocks are only recorded once it has committed. A block reaches the enforcement points
 * right away and cannot be retracted, so a rolled back deletion must not leave the device locked out — the price is a moment between commit and block
 * in which the device's current access tokens still pass. A block failing after the commit is logged only (see [blockSession]).
 *
 * A user session can be shared with other clients through SSO, which then lose it too; the enforcement points block per `sid` and cannot tell their
 * tokens apart.
 *
 * Must run before the client is removed: the sessions are looked up by client.
 *
 * @return the ids of the revoked sessions
 */
fun revokeClientSessions(session: KeycloakSession, realm: RealmModel, client: ClientModel): List<String> {
  val sessions = session.sessions()
  val sids =
      // read-only models, only their ids are used: endSession loads each one again
      (sessions.readOnlyStreamOfflineUserSessions(realm, client, -1, -1).toList() + sessions.readOnlyStreamUserSessions(realm, client, -1, -1).toList())
          .map { it.id }
          .distinct()

  sids.forEach { endSession(session, realm, it) }

  if (sids.isNotEmpty()) {
    session.transactionManager.enlistAfterCompletion(
        object : AbstractKeycloakTransaction() {
          override fun commitImpl() {
            sids.forEach { blockSession(session, it) }
          }

          override fun rollbackImpl() {
            log.debugf("not blocking sessions »%s«, the transaction ending them was rolled back", sids)
          }
        }
    )
  }
  return sids
}
