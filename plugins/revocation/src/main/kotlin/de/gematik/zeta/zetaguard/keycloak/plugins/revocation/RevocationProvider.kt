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

import jakarta.ws.rs.BadRequestException
import jakarta.ws.rs.Consumes
import jakarta.ws.rs.GET
import jakarta.ws.rs.POST
import jakarta.ws.rs.Path
import jakarta.ws.rs.Produces
import jakarta.ws.rs.core.Context
import jakarta.ws.rs.core.MediaType
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.sse.OutboundSseEvent
import jakarta.ws.rs.sse.Sse
import jakarta.ws.rs.sse.SseEventSink
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import org.jboss.logging.Logger
import org.keycloak.models.KeycloakSession
import org.keycloak.representations.AccessToken
import org.keycloak.services.managers.AuthenticationManager
import org.keycloak.services.resource.RealmResourceProvider

private val log = Logger.getLogger(RevocationProvider::class.java)

private const val HEARTBEAT_SECONDS = 20L

/**
 * Revocation API under .../realms/{realm}/zeta-guard-revocation.
 *
 * Both verbs live on the same URI:
 * - POST: report an offending access token. Authorization is possession of a token this realm signed — the only parties able to present one are its
 *   owner and whoever compromised it, and both should end that session.
 * - GET: subscribe to the block list as server-sent events; the connect delivers a snapshot, so a reconnect is also the reconciliation mechanism and
 *   no separate catch-up is needed.
 */
class RevocationProvider(private val session: KeycloakSession, private val scheduler: ScheduledExecutorService) : RealmResourceProvider {

  override fun getResource(): Any = this

  override fun close() {
    // no-op: subscriptions outlive the session, see stream()
  }

  @POST
  @Path("")
  @Consumes(MediaType.TEXT_PLAIN)
  fun report(token: String?): Response {
    val raw = token?.trim().orEmpty()
    if (raw.isEmpty()) throw BadRequestException("empty body, expected an access token")

    // Verifies the signature against this realm's keys; an unsigned or foreign
    // token must not be able to revoke anything.
    val access = session.tokens().decode(raw, AccessToken::class.java) ?: throw BadRequestException("not a token issued by this realm")

    val sid = access.sessionId ?: throw BadRequestException("token has no session")
    val until = access.exp ?: throw BadRequestException("token has no exp")
    val block = Block(`when` = System.currentTimeMillis() / 1000, until = until, what = sid)

    BlockStore.of(session).put(block)
    revokeSession(sid)

    log.infof("revoked session %s until %d", sid, until)
    return Response.noContent().build()
  }

  /**
   * The sink is asynchronous: this method returns immediately and the request thread goes back to the pool, so a subscriber costs a connection rather
   * than a parked thread. Everything the stream needs is captured up front — the KeycloakSession is closed once this returns, while the cache behind
   * [BlockStore] is owned by the cache manager and stays valid.
   */
  @GET
  @Path("")
  @Produces(MediaType.SERVER_SENT_EVENTS)
  fun stream(@Context sse: Sse, @Context sink: SseEventSink) {
    val store = BlockStore.of(session)
    val closers = Closers()
    val cleanup: () -> Unit = { closers.closeAll() }

    // Subscribe before snapshotting: a block landing in between then arrives as a delta instead of falling into the gap between the two.
    val subscription = store.subscribe { block -> emit(sink, sse.newEvent(block.toJson()), cleanup) }
    closers.add { subscription.close() }

    // Blocks are rare, so the stream is mostly idle; comments keep the connection (and any proxy in between) from being reaped.
    val heartbeat =
        scheduler.scheduleAtFixedRate(
            { emit(sink, sse.newEventBuilder().comment("ping").build(), cleanup) },
            HEARTBEAT_SECONDS,
            HEARTBEAT_SECONDS,
            TimeUnit.SECONDS,
        )
    closers.add { heartbeat.cancel(false) }
    closers.add { sink.close() }

    store.snapshot().forEach { block -> emit(sink, sse.newEvent(block.toJson()), cleanup) }
  }

  private fun emit(sink: SseEventSink, event: OutboundSseEvent, cleanup: () -> Unit) {
    if (sink.isClosed) {
      cleanup()
      return
    }
    runCatching { sink.send(event) }
        .onSuccess { pending -> pending.whenComplete { _, error -> if (error != null) cleanup() } }
        .onFailure { cleanup() }
  }

  private fun revokeSession(sid: String) {
    val realm = session.context.realm
    val userSession = session.sessions().getUserSession(realm, sid) ?: return
    AuthenticationManager.backchannelLogout(
        session,
        realm,
        userSession,
        session.context.uri,
        session.context.connection,
        session.context.requestHeaders,
        true,
    )
  }
}

/**
 * Release actions for one stream, safe to register and to run from any thread and in any order.
 *
 * Both properties are load-bearing. The subscriber callback runs on a cache thread and the heartbeat on the scheduler, so either can trigger cleanup
 * while the request thread is still registering — a plain list would be mutated and iterated concurrently. And cleanup can win the race against a
 * registration: a block arriving between `subscribe` and the heartbeat being scheduled ends the stream before the heartbeat's canceller exists, so a
 * "closed already, ignore" implementation would leave that heartbeat pinging a dead sink every 20s for the life of the process.
 *
 * Draining by [ConcurrentLinkedQueue.poll] gives each action exactly one run, in registration order, no matter who calls what when.
 */
internal class Closers {
  private val closed = AtomicBoolean(false)
  private val actions = ConcurrentLinkedQueue<() -> Unit>()

  /** Register [action], or run it now if this is already closed. */
  fun add(action: () -> Unit) {
    actions.add(action)
    if (closed.get()) drain()
  }

  fun closeAll() {
    closed.set(true)
    drain()
  }

  private fun drain() {
    while (true) {
      val action = actions.poll() ?: return
      runCatching(action)
    }
  }
}
