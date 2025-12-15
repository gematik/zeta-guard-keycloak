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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb.opa

import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import io.mockk.every
import io.mockk.mockk
import io.mockk.unmockkAll
import java.io.ByteArrayInputStream
import org.apache.http.HttpEntity
import org.apache.http.StatusLine
import org.apache.http.client.methods.CloseableHttpResponse
import org.apache.http.client.methods.HttpUriRequest
import org.apache.http.impl.client.CloseableHttpClient
import org.jboss.logging.Logger

class OpaDecisionClientMappingTest :
    FunSpec({
      beforeSpec { unmockkAll() }
      afterSpec { unmockkAll() }
      val log: Logger = Logger.getLogger("test")
      val cfg = OPAConfig(opaBaseUrl = "http://opa:8181/", decisionPath = "v1/data/zeta/authz/decision")

      test("HTTP 4xx maps to Decision.Error") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val resp = mockResponse(400, null)
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Error) shouldBe true
      }

      test("HTTP 5xx maps to Decision.Error") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val resp = mockResponse(500, null)
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Error) shouldBe true
      }

      test("Invalid JSON on 200 maps to Decision.Error") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val entity = mockEntity("not json")
        val resp = mockResponse(200, entity)
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Error) shouldBe true
      }

      test("Object decision allow=true maps to Decision.Allow (with ttl)") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val body =
            """
              {"decision_id":"abc","result":{"allow":true,"ttl":{"access_token":300,"refresh_token":86400}}}
            """
                .trimIndent()
        val resp = mockResponse(200, mockEntity(body))
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Allow) shouldBe true
      }

      test("Object decision allow=false maps to Decision.Deny with reasons (object map)") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val body =
            """
              {"decision_id":"abc","result":{"allow":false,"reasons":{
                "Client product or version is not allowed": true,
                "One or more requested audiences are not allowed": true,
                "One or more requested scopes are not allowed": true,
                "User profession is not allowed": true
              }}}
            """
                .trimIndent()
        val resp = mockResponse(200, mockEntity(body))
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Deny) shouldBe true
      }

      test("Malformed object (missing allow) maps to Decision.Error") {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val body =
            """
              {"decision_id":"abc","result":{}}
            """
                .trimIndent()
        val resp = mockResponse(200, mockEntity(body))
        every { httpClient.execute(any<HttpUriRequest>()) } returns resp
        val res = OpaDecisionClient.evaluate(httpClient, cfg, "{}", log)
        (res is Decision.Error) shouldBe true
      }
    })

private fun mockResponse(status: Int, entity: HttpEntity?): CloseableHttpResponse {
  val resp = mockk<CloseableHttpResponse>(relaxed = true)
  val statusLine = mockk<StatusLine>(relaxed = true)
  every { statusLine.statusCode } returns status
  every { resp.statusLine } returns statusLine
  every { resp.entity } returns entity
  return resp
}

private fun mockEntity(body: String): HttpEntity {
  val entity = mockk<HttpEntity>(relaxed = true)
  every { entity.content } returns ByteArrayInputStream(body.toByteArray())
  return entity
}
