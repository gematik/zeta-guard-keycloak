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

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import de.gematik.zeta.zetaguard.keycloak.commons.ADMIN_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_CLIENT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.it.ClientAssertionTokenHelper.clientAssertionTokenGenerator
import io.kotest.assertions.arrow.core.shouldBeRight
import io.kotest.assertions.nondeterministic.eventually
import io.kotest.assertions.nondeterministic.eventuallyConfig
import io.kotest.core.annotation.Condition
import io.kotest.core.annotation.EnabledIf
import io.kotest.core.spec.Spec
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeEmpty
import java.time.Instant
import kotlin.reflect.KClass
import kotlin.time.Duration.Companion.seconds
import org.apache.http.client.methods.RequestBuilder
import org.apache.http.impl.client.HttpClients
import org.apache.http.util.EntityUtils

class TracingEnabledCondition : Condition {
  override fun evaluate(kclass: KClass<out Spec>): Boolean = Docker.tracingEnabled
}

@EnabledIf(TracingEnabledCondition::class)
class TracingIT : ZetaGuardFunSpecIT() {

  private val objectMapper = ObjectMapper()
  private val httpClient = HttpClients.createDefault()

  private fun tempoBaseUrl(): String = "http://${Docker.tempoHost}:${Docker.tempoPort}"

  private fun searchTraceQL(query: String, limit: Int = 20, start: Instant? = null): JsonNode {
    val startParam = start?.let { "&start=${it.epochSecond}&end=${Instant.now().plusSeconds(60).epochSecond}" } ?: ""
    val url = "${tempoBaseUrl()}/api/search?q=${java.net.URLEncoder.encode(query, "UTF-8")}&limit=$limit$startParam"

    val request = RequestBuilder.get(url).build()
    val response = httpClient.execute(request)
    val body = EntityUtils.toString(response.entity)

    Docker.log.info("Tempo search [{}] url=[{}] -> HTTP {} | {}", query, url, response.statusLine.statusCode, body.take(500))
    response.statusLine.statusCode shouldBe 200
    return objectMapper.readTree(body)
  }

  private fun getTrace(traceId: String): JsonNode {
    val url = "${tempoBaseUrl()}/api/traces/$traceId"

    val request = RequestBuilder.get(url).build()
    val response = httpClient.execute(request)
    val body = EntityUtils.toString(response.entity)

    Docker.log.info("Tempo get trace [{}] -> HTTP {}", traceId, response.statusLine.statusCode)
    response.statusLine.statusCode shouldBe 200
    return objectMapper.readTree(body)
  }

  private suspend fun awaitTraceId(query: String, start: Instant): String {
    val waitConfig = eventuallyConfig {
      duration = 30.seconds
      interval = 3.seconds
      initialDelay = 5.seconds
    }
    return eventually(waitConfig) {
      val result = searchTraceQL(query, start = start)
      val traces = result.get("traces")
      traces.shouldNotBeEmpty()
      traces.first().path("traceID").asText()
    }
  }

  private fun collectTraceAttributes(trace: JsonNode): Map<String, String> {
    val attributes = mutableMapOf<String, String>()
    trace.path("batches").forEach { batch ->
      batch.path("scopeSpans").forEach { scopeSpan ->
        scopeSpan.path("spans").forEach { span ->
          span.path("attributes").forEach { attr ->
            val key = attr.path("key").asText()
            val value = attr.path("value").path("stringValue").asText()
                .ifEmpty { attr.path("value").path("intValue").asText() }
            if (key.isNotEmpty() && value.isNotEmpty()) {
              attributes[key] = value
            }
          }
        }
      }
    }
    return attributes
  }

  init {
    val registrationRoute = "/realms/{realm}/clients-registrations/{provider}"
    val tokenRoute = "/realms/{realm}/protocol/{protocol}/token"

    val requiredAttributes = listOf(
        "app.installation.id",
        "client.address",
        "user_agent.original",
        "http.request.method_original",
        "http.route",
        "server.address",
        "http.response.status_code",
    )

    test("Client registration produces traces with required attributes") {
      val start = Instant.now()
      val clientResponse = keycloakWebClient.createClientOIDC(clientAssertionTokenGenerator.keys.jwks).shouldBeRight().reponseObject

      try {
        val traceId = awaitTraceId("""{ span.http.route = "$registrationRoute" }""", start)
        val attributes = collectTraceAttributes(getTrace(traceId))

        val missing = requiredAttributes.filterNot { it in attributes }
        Docker.log.info("Client registration trace attributes: {}", attributes)
        Docker.log.info("Missing attributes: {}", missing)

        missing shouldBe emptyList()
        attributes["http.request.method_original"] shouldBe "POST"
        attributes["http.route"] shouldBe registrationRoute
        attributes["app.installation.id"].shouldNotBeEmpty()
      } finally {
        keycloakWebClient.withKeycloak(clientId = ADMIN_CLIENT) {
          realm(ZETA_REALM).clients().get(clientResponse.clientId).remove()
        }
      }
    }

    test("Token exchange produces traces with required attributes") {
      val start = Instant.now()
      val nonce = createNonce()
      val jwt = clientAssertionTokenGenerator.generateClientAssertion(audiences = listOf(clientAssertionAudience), nonceString = nonce)
      val smcbToken = createSMCBToken(nonce)
      testExchangeToken(smcbToken, clientAssertion = jwt)

      val traceId = awaitTraceId("""{ span.http.route = "$tokenRoute" && span.app.installation.id != "" && status != error }""", start)
      val attributes = collectTraceAttributes(getTrace(traceId))

      val missing = requiredAttributes.filterNot { it in attributes }
      Docker.log.info("Token exchange trace attributes: {}", attributes)
      Docker.log.info("Missing attributes: {}", missing)

      missing shouldBe emptyList()
      attributes["http.request.method_original"] shouldBe "POST"
      attributes["http.route"] shouldBe tokenRoute
      attributes["app.installation.id"] shouldBe ZETA_CLIENT
    }
  }
}
