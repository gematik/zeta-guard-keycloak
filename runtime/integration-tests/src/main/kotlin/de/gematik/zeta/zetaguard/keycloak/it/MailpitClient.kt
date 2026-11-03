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

import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse.BodyHandlers
import java.nio.charset.StandardCharsets.UTF_8
import org.keycloak.util.JsonSerialization

private val OTP_REGEX = Regex("""\b(\d{6})\b""")

/** Reads the mails caught by Mailpit over its REST API, see [https://mailpit.axllent.org/docs/api-v1/]. */
private const val MAX_MESSAGES = 1000

class MailpitClient(private val baseUrl: String) {
  private val http = HttpClient.newHttpClient()

  fun latestOtp(recipient: String): String {
    val query = URLEncoder.encode("to:\"$recipient\"", UTF_8)
    // Search results are ordered newest first; `to:` matches substrings, so the recipient is compared exactly
    val id =
        JsonSerialization.mapper
            .readTree(get("/api/v1/search?query=$query"))
            .path("messages")
            .first { message -> message.path("To").any { it.path("Address").asText().equals(recipient, ignoreCase = true) } }
            .path("ID")
            .asText()

    return checkNotNull(OTP_REGEX.find(JsonSerialization.mapper.readTree(get("/api/v1/message/$id")).path("Text").asText())).groupValues[1]
  }

  /** The plain text bodies of all mails to [recipient], oldest first. */
  fun plainBodies(recipient: String): List<String> {
    val query = URLEncoder.encode("to:\"$recipient\"", UTF_8)

    // the search returns at most 50 messages unless told otherwise, newest first
    return JsonSerialization.mapper
        .readTree(get("/api/v1/search?query=$query&limit=$MAX_MESSAGES"))
        .path("messages")
        .filter { message -> message.path("To").any { it.path("Address").asText().equals(recipient, ignoreCase = true) } }
        .map { it.path("ID").asText() }
        .reversed()
        .map { JsonSerialization.mapper.readTree(get("/api/v1/message/$it")).path("Text").asText() }
  }

  private fun get(path: String) = http.send(HttpRequest.newBuilder(URI.create("$baseUrl$path")).build(), BodyHandlers.ofString()).body()
}
