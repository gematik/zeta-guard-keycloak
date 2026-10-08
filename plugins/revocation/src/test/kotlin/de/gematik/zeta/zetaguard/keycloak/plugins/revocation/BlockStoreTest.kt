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
import org.infinispan.configuration.cache.ConfigurationBuilder
import org.infinispan.manager.DefaultCacheManager

private const val SID = "mzEPAZMnxCwiDaN8D7DVDi91"

/**
 * The merge rules of [BlockStore.put], against a real cache rather than a mock — the interesting behaviour is Infinispan's compare-and-set and its
 * entry events, which a mock would only assert back to us.
 *
 * The cache is local: replication needs a cluster, and the merge decides everything before a write happens.
 */
class BlockStoreTest :
    StringSpec({
      val manager = autoClose(DefaultCacheManager())
      manager.defineConfiguration(REVOCATION_CACHE, ConfigurationBuilder().build())

      lateinit var store: EmbeddedBlockStore
      lateinit var received: MutableList<Block>

      beforeTest {
        manager.getCache<String, String>(REVOCATION_CACHE).clear()
        store = EmbeddedBlockStore(manager.getCache(REVOCATION_CACHE))
        received = mutableListOf()
      }

      fun now() = System.currentTimeMillis() / 1000

      "stores a block and hands it to subscribers" {
        val block = Block(`when` = now(), until = now() + 300, what = SID)

        store.subscribe { received += it }.use { store.put(block) }

        store.snapshot() shouldContainExactly listOf(block)
        received shouldContainExactly listOf(block)
      }

      "extends a block whose window grew, and says so" {
        val first = Block(`when` = now(), until = now() + 300, what = SID)
        val later = Block(`when` = now() + 10, until = now() + 600, what = SID)

        store
            .subscribe { received += it }
            .use {
              store.put(first)
              store.put(later)
            }

        // The later bound wins, but the block still dates from when the session was first blocked.
        val merged = later.copy(`when` = first.`when`)
        store.snapshot() shouldContainExactly listOf(merged)
        received shouldContainExactly listOf(first, merged)
      }

      "ignores a block that would shorten an existing one" {
        val first = Block(`when` = now(), until = now() + 600, what = SID)
        val shorter = Block(`when` = now(), until = now() + 300, what = SID)

        store
            .subscribe { received += it }
            .use {
              store.put(first)
              store.put(shorter)
            }

        store.snapshot() shouldContainExactly listOf(first)
        // No write happened, so subscribers are not woken for something they already know.
        received shouldContainExactly listOf(first)
      }

      "ignores a repeated report of the same block" {
        val block = Block(`when` = now(), until = now() + 300, what = SID)

        store
            .subscribe { received += it }
            .use {
              store.put(block)
              store.put(block)
            }

        store.snapshot() shouldContainExactly listOf(block)
        received shouldContainExactly listOf(block)
      }

      "keeps blocks of different sessions apart" {
        val a = Block(`when` = now(), until = now() + 300, what = "$SID-a")
        val b = Block(`when` = now(), until = now() + 300, what = "$SID-b")

        store.put(a)
        store.put(b)

        store.snapshot().map { it.what }.sorted() shouldBe listOf(a.what, b.what)
      }

      "probing does not leave anything behind" {
        store.probe()

        store.snapshot().shouldBeEmpty()
      }

      "stops delivering after a subscription is closed" {
        store.subscribe { received += it }.close()

        store.put(Block(`when` = now(), until = now() + 300, what = SID))

        received.shouldBeEmpty()
      }
    })
