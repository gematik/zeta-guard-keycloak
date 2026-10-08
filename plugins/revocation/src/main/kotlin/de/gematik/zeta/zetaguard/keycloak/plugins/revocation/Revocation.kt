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

import com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.module.kotlin.registerKotlinModule
import java.util.concurrent.TimeUnit
import org.infinispan.Cache
import org.infinispan.client.hotrod.RemoteCache
import org.infinispan.client.hotrod.annotation.ClientCacheEntryCreated
import org.infinispan.client.hotrod.annotation.ClientCacheEntryModified
import org.infinispan.client.hotrod.annotation.ClientListener
import org.infinispan.client.hotrod.event.ClientCacheEntryCreatedEvent
import org.infinispan.client.hotrod.event.ClientCacheEntryModifiedEvent
import org.infinispan.commons.api.BasicCache
import org.infinispan.configuration.cache.CacheMode
import org.infinispan.configuration.cache.ConfigurationBuilder
import org.infinispan.notifications.Listener
import org.infinispan.notifications.cachelistener.annotation.CacheEntryCreated
import org.infinispan.notifications.cachelistener.annotation.CacheEntryModified
import org.infinispan.notifications.cachelistener.event.CacheEntryCreatedEvent
import org.infinispan.notifications.cachelistener.event.CacheEntryModifiedEvent
import org.jboss.logging.Logger
import org.keycloak.connections.infinispan.InfinispanConnectionProvider
import org.keycloak.infinispan.util.InfinispanUtils
import org.keycloak.models.KeycloakSession

private val log = Logger.getLogger("de.gematik.zeta.zetaguard.keycloak.plugins.revocation.BlockStore")

/**
 * Cache holding blocked sessions, keyed by `sid`, value = the JSON of [Block].
 *
 * In embedded mode it is defined at startup by [defineEmbeddedCache]; in dedicated-Infinispan mode it must exist on the server.
 */
const val REVOCATION_CACHE = "zetaGuardRevocations"

/**
 * Unknown fields are tolerated, so that during a rolling upgrade a node still running the old code can read what a newer one wrote into the shared
 * cache instead of failing on the entry.
 */
internal val MAPPER: ObjectMapper = ObjectMapper().registerKotlinModule().configure(FAIL_ON_UNKNOWN_PROPERTIES, false)

/**
 * A blocked session, as stored and as sent to subscribers. Field names are the wire contract with the PEP and are spelled exactly as they go over the
 * wire; `until` is the point after which the block may be forgotten, and is derived from the offending token's lifetime — never from the session,
 * which is destroyed on revocation.
 */
data class Block(val `when`: Long, val until: Long, val what: String) {
  fun toJson(): String = MAPPER.writeValueAsString(this)

  companion object {
    fun fromJson(json: String): Block = MAPPER.readValue(json, Block::class.java)
  }
}

/**
 * The block list, abstracted over Keycloak's two Infinispan topologies: embedded caches expose `org.infinispan.Cache` and deliver entry events with
 * their value, dedicated servers expose a Hot Rod `RemoteCache` whose events carry only the key.
 */
interface BlockStore {
  /** Store a block, expiring it at [Block.until]. Idempotent for a given sid. */
  fun put(block: Block)

  /** Every block currently held, for the snapshot a subscriber gets on connect. */
  fun snapshot(): List<Block>

  /** Observe blocks added on THIS node's view of the cache. */
  fun subscribe(onBlock: (Block) -> Unit): AutoCloseable

  /** Round-trip to the cache, so a missing or unreachable one surfaces here and not on a request. */
  fun probe()

  companion object {
    /**
     * Resolve the store from a session. The returned store outlives the session: the cache is owned by the cache manager, so it stays valid for a
     * streaming response that keeps writing after the JAX-RS method returned.
     */
    fun of(session: KeycloakSession): BlockStore {
      val connection = session.getProvider(InfinispanConnectionProvider::class.java)
      return if (InfinispanUtils.isRemoteInfinispan()) {
        RemoteBlockStore(connection.getRemoteCache(REVOCATION_CACHE))
      } else {
        EmbeddedBlockStore(connection.getCache(REVOCATION_CACHE))
      }
    }
  }
}

/**
 * Declare the embedded cache, so no deployment has to carry a hand-maintained copy of Keycloak's cache XML just to add one cache. Keycloak's cache
 * manager defines no default configuration, so an undeclared cache cannot be created on demand — asking for it fails with ISPN000436 instead.
 *
 * Every node runs this, and it only touches its own manager: replication needs the configuration present on all of them.
 */
fun defineEmbeddedCache(session: KeycloakSession) {
  val connection = session.getProvider(InfinispanConnectionProvider::class.java)
  // The manager is not on the SPI, but any Keycloak cache can hand it over.
  val manager = connection.getCache<Any, Any>(InfinispanConnectionProvider.WORK_CACHE_NAME).cacheManager
  if (manager.getCacheConfiguration(REVOCATION_CACHE) != null) return

  val builder = ConfigurationBuilder()
  // Entries expire by themselves (see lifespanSeconds), and they are neither evicted nor bounded: dropping a block would silently un-revoke a
  // session.
  if (manager.cacheManagerConfiguration.isClustered) {
    // Replicated and synchronous: once a report is answered, the block is on every node, including the ones holding subscriptions.
    builder.clustering().cacheMode(CacheMode.REPL_SYNC)
  } else {
    builder.clustering().cacheMode(CacheMode.LOCAL)
  }
  manager.defineConfiguration(REVOCATION_CACHE, builder.build())
}

/** A sid that cannot occur, so the probe never reports a real block as present. */
private const val PROBE_KEY = ""

/** Enough attempts to outlast contention on one sid, which only two writers ever have. */
private const val MERGE_ATTEMPTS = 3

private fun lifespanSeconds(block: Block): Long = (block.until - System.currentTimeMillis() / 1000).coerceAtLeast(1)

/**
 * Store [block] unless the sid is already blocked at least as long, keeping the later `until` and the earlier `when`. A session can be reported and
 * then end through Keycloak, or end twice, and the two paths derive `until` differently; the union is the only answer that never shortens a block.
 *
 * Writing only on a real extension is also what makes the entry events meaningful: every event a subscriber sees carries a block it does not have
 * yet. Both topologies share this because `BasicCache` is the common ancestor of embedded and Hot Rod caches.
 */
private fun BasicCache<String, String>.putMerged(block: Block) {
  repeat(MERGE_ATTEMPTS) {
    val existingJson = get(block.what)
    if (existingJson == null) {
      if (putIfAbsent(block.what, block.toJson(), lifespanSeconds(block), TimeUnit.SECONDS) == null) return
      return@repeat // lost the race against another writer; retry as an extension
    }
    val existing = Block.fromJson(existingJson)
    if (existing.until >= block.until) return
    val merged = block.copy(`when` = minOf(existing.`when`, block.`when`))
    if (replace(block.what, existingJson, merged.toJson(), lifespanSeconds(merged), TimeUnit.SECONDS)) return
  }
  log.warnf("gave up extending the block for session %s after %d attempts", block.what, MERGE_ATTEMPTS)
}

internal class EmbeddedBlockStore(private val cache: Cache<String, String>) : BlockStore {
  override fun put(block: Block) = cache.putMerged(block)

  override fun snapshot(): List<Block> = cache.values.map(Block::fromJson)

  override fun probe() {
    cache.containsKey(PROBE_KEY)
  }

  override fun subscribe(onBlock: (Block) -> Unit): AutoCloseable {
    val listener = EmbeddedListener(onBlock)
    cache.addListener(listener)
    return AutoCloseable { cache.removeListener(listener) }
  }

  /** A block that extends an existing one arrives as a modification, so both events matter. */
  @Listener(clustered = true)
  inner class EmbeddedListener(private val onBlock: (Block) -> Unit) {
    @CacheEntryCreated
    fun created(event: CacheEntryCreatedEvent<String, String>) {
      if (!event.isPre) event.value?.let { onBlock(Block.fromJson(it)) }
    }

    @CacheEntryModified
    fun modified(event: CacheEntryModifiedEvent<String, String>) {
      if (!event.isPre) event.newValue?.let { onBlock(Block.fromJson(it)) }
    }
  }
}

internal class RemoteBlockStore(private val cache: RemoteCache<String, String>) : BlockStore {
  override fun put(block: Block) = cache.putMerged(block)

  override fun snapshot(): List<Block> = cache.keys.mapNotNull { key -> cache[key]?.let(Block::fromJson) }

  override fun probe() {
    cache.containsKey(PROBE_KEY)
  }

  override fun subscribe(onBlock: (Block) -> Unit): AutoCloseable {
    val listener = RemoteListener(onBlock)
    cache.addClientListener(listener)
    return AutoCloseable { cache.removeClientListener(listener) }
  }

  /** Hot Rod events carry only the key, so the value is fetched to build the block. */
  @ClientListener
  inner class RemoteListener(private val onBlock: (Block) -> Unit) {
    @ClientCacheEntryCreated
    fun created(event: ClientCacheEntryCreatedEvent<String>) {
      emit(event.key)
    }

    @ClientCacheEntryModified
    fun modified(event: ClientCacheEntryModifiedEvent<String>) {
      emit(event.key)
    }

    private fun emit(key: String) {
      cache[key]?.let { onBlock(Block.fromJson(it)) }
    }
  }
}
