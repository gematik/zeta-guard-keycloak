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
import io.kotest.matchers.collections.shouldContainExactly
import io.kotest.matchers.shouldBe
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * The ordering and threading guarantees [Closers] exists for: a stream can end from a cache thread or the heartbeat thread while the request thread
 * is still registering, so "closed already" must not mean "silently leaked".
 */
class ClosersTest :
    StringSpec({
      "runs actions once, in registration order" {
        val run = mutableListOf<String>()
        val closers = Closers()
        closers.add { run += "subscription" }
        closers.add { run += "heartbeat" }
        closers.add { run += "sink" }

        closers.closeAll()
        closers.closeAll() // a second cleanup (e.g. heartbeat and subscriber both failing) must not re-run anything

        run shouldContainExactly listOf("subscription", "heartbeat", "sink")
      }

      "runs an action registered after close — the heartbeat-leak case" {
        var cancelled = false
        val closers = Closers()

        // The stream dies during subscribe(), before the heartbeat's canceller can be registered.
        closers.closeAll()
        closers.add { cancelled = true }

        cancelled shouldBe true
      }

      "runs every action exactly once under concurrent close and register" {
        repeat(50) {
          val closers = Closers()
          val runs = AtomicInteger()
          val start = CountDownLatch(1)
          val pool = Executors.newFixedThreadPool(4)
          try {
            val tasks =
                (1..3).map {
                  pool.submit {
                    start.await()
                    closers.add { runs.incrementAndGet() }
                  }
                } +
                    pool.submit {
                      start.await()
                      closers.closeAll()
                    }
            start.countDown()
            tasks.forEach { it.get(5, TimeUnit.SECONDS) }
            closers.closeAll() // whoever lost the race still gets drained
          } finally {
            pool.shutdownNow()
          }
          runs.get() shouldBe 3
        }
      }
    })
