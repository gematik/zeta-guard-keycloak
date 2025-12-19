/*-
 * #%L
 * keycloak-zeta
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import com.fasterxml.jackson.databind.JsonNode
import java.nio.charset.StandardCharsets
import org.apache.http.HttpHeaders
import org.apache.http.HttpStatus.SC_OK
import org.apache.http.client.config.RequestConfig
import org.apache.http.client.methods.HttpPost
import org.apache.http.entity.ContentType
import org.apache.http.entity.StringEntity
import org.apache.http.impl.client.CloseableHttpClient
import org.jboss.logging.Logger
import org.keycloak.util.JsonSerialization

object OpaDecisionClient {
  fun evaluate(httpClient: CloseableHttpClient, opaConfig: OPAConfig, bodyJson: String, log: Logger): Decision {
    val effective = OpaConfigResolver.normalize(opaConfig)
    val url = effective.opaBaseUrl + effective.decisionPath
    val request = buildRequest(url, effective, bodyJson)
    val start = System.currentTimeMillis()

    return try {
      httpClient.execute(request).use { response ->
        val status = response.statusLine?.statusCode ?: -1
        val dur = System.currentTimeMillis() - start
        log.infof("**OPA TokenPolicy** OPA status=%d (dur=%dms)", status, dur)

        when (status) {
          SC_OK -> {
            val entity = response.entity ?: return Decision.Error(null)
            val bytes = entity.content.use { it.readBytes() }

            parseDecision(bytes, log)
          }

          in 400..499 -> Decision.Error(null)
          else -> Decision.Error(null)
        }
      }
    } catch (ex: Exception) {
      log.warn("**OPA TokenPolicy** error calling OPA", ex)
      Decision.Error(ex)
    }
  }

  private fun buildRequest(url: String, effective: OPAConfig, bodyJson: String): HttpPost =
      HttpPost(url).apply {
        addHeader(HttpHeaders.ACCEPT, "application/json")
        addHeader(HttpHeaders.CONTENT_TYPE, "application/json")
        entity = StringEntity(bodyJson, ContentType.APPLICATION_JSON.withCharset(StandardCharsets.UTF_8))
        this.config =
            RequestConfig.custom()
                .setConnectTimeout(effective.connectionTimeoutMs)
                .setConnectionRequestTimeout(effective.connectionTimeoutMs)
                .setSocketTimeout(effective.readTimeoutMs)
                .build()
      }

  private fun parseDecision(bytes: ByteArray, log: Logger): Decision {
    val node = JsonSerialization.mapper.readTree(bytes)
    val resultNode = node["result"] ?: return Decision.Error(null)

    return when {
      resultNode.isObject -> {
        val allowNode = resultNode["allow"]
        if (allowNode != null && allowNode.isBoolean) {
          val allow = allowNode.asBoolean()
          if (allow) {
            val ttlNode = resultNode["ttl"]
            val accessTtl = ttlNode?.get("access_token")?.takeIf { it.isInt }?.asInt()
            val refreshTtl = ttlNode?.get("refresh_token")?.takeIf { it.isInt }?.asInt()
            log.infof("**OPA TokenPolicy** allow=true access_ttl=%s refresh_ttl=%s", accessTtl, refreshTtl)
            Decision.Allow(accessTtl, refreshTtl)
          } else {
            val reasonsNode = resultNode["reasons"]
            val reasonsList = reasonsList(reasonsNode)
            log.infof("**OPA TokenPolicy** allow=false reasons=%d", reasonsList.size)
            Decision.Deny(reasonsList)
          }
        } else {
          Decision.Error(null)
        }
      }

      resultNode.isBoolean -> {
        val allow = resultNode.asBoolean()
        log.infof("**OPA TokenPolicy** allow=%s", allow)
        if (allow) Decision.Allow() else Decision.Deny(emptyList())
      }

      else -> Decision.Error(null)
    }
  }

  private fun reasonsList(node: JsonNode?): List<String> =
      when {
        node == null -> emptyList()
        node.isArray -> node.map { it.asText() }
        node.isObject -> node.properties().asSequence().filter { it.value.asBoolean(true) }.map { it.key }.toList()
        else -> listOf(node.asText())
      }
}
