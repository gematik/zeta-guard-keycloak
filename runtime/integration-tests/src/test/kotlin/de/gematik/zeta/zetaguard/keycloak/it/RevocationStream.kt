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
package de.gematik.zeta.zetaguard.keycloak.it

import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import io.kotest.assertions.fail
import io.kotest.matchers.shouldBe
import java.io.BufferedReader
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import org.apache.http.HttpHeaders.ACCEPT
import org.apache.http.HttpStatus.SC_OK
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.client.methods.RequestBuilder.get

private const val SSE_MEDIA_TYPE = "text/event-stream"

/**
 * A subscriber to the revocation stream, for tests that need to observe what the PEP would observe.
 *
 * The response body never ends, so it is drained on its own thread and completed events are handed over through a queue; [awaitBlock] is the only way
 * to read them, which keeps every assertion bounded in time. Blocks are kept as raw maps on purpose: a test that decoded them into the production
 * class could not notice a rename of the fields the PEP parses.
 */
class RevocationStream(client: KeycloakWebClient) : AutoCloseable {
  private val mapper = ObjectMapper()
  private val blocks = LinkedBlockingQueue<Map<String, Any>>()
  private val seen = mutableListOf<Map<String, Any>>()
  private val request: HttpUriRequest = get(client.uriBuilder().revocationUrl()).addHeader(ACCEPT, SSE_MEDIA_TYPE).build()
  private val reader: BufferedReader

  private val worker =
      Thread {
            try {
              drain()
            } catch (_: Exception) {
              // the stream is closed by close(), which surfaces here as an abort
            }
          }
          .apply { isDaemon = true }

  init {
    val response = client.httpClient().execute(request)
    response.statusLine.statusCode shouldBe SC_OK
    response.getFirstHeader("Content-Type").value shouldBe SSE_MEDIA_TYPE
    reader = response.entity.content.bufferedReader()
    worker.start()
  }

  /**
   * Wait for the block of [sid], skipping unrelated ones — other tests share the realm, and their revocations land in the same stream.
   *
   * @return the block as it arrived on the wire
   */
  fun awaitBlock(sid: String, timeout: Duration = 15.seconds): Map<String, Any> {
    val deadline = System.nanoTime() + timeout.inWholeNanoseconds

    while (true) {
      val remaining = deadline - System.nanoTime()
      if (remaining <= 0) fail("no block for session $sid within $timeout, saw: $seen")

      val block = blocks.poll(remaining, TimeUnit.NANOSECONDS) ?: continue
      seen += block
      if (block[FIELD_WHAT] == sid) return block
    }
  }

  override fun close() {
    request.abort()
    worker.interrupt()
  }

  /**
   * Assembles events per the event-stream format: `data:` lines accumulate, a blank line ends the event. Everything else is ignored, which is what
   * the spec demands and what silently swallows the keep-alive comments.
   */
  private fun drain() {
    val data = StringBuilder()

    reader.forEachLine { line ->
      when {
        line.startsWith("data:") -> data.append(line.removePrefix("data:").removePrefix(" "))
        line.isEmpty() && data.isNotEmpty() -> {
          @Suppress("UNCHECKED_CAST") blocks.put(mapper.readValue(data.toString(), Map::class.java) as Map<String, Any>)
          data.clear()
        }
      }
    }
  }

  companion object {
    /** The wire contract with the PEP; see its `block_list::Block`. */
    const val FIELD_WHEN = "when"
    const val FIELD_UNTIL = "until"
    const val FIELD_WHAT = "what"
  }
}
