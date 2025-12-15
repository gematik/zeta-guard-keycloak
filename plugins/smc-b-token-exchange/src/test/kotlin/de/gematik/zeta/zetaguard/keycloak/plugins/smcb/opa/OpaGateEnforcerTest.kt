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

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import org.apache.http.impl.client.CloseableHttpClient
import org.jboss.logging.Logger
import org.junit.jupiter.api.Assertions.assertEquals

class OpaGateEnforcerTest :
    StringSpec({
      val log: Logger = Logger.getLogger("test")
      val cfg = OPAConfig()

      "returns Skip for non token-exchange grant type" {
        val input = OpaGateInput(grantType = "client_credentials", scopes = emptyList(), audiences = null, ipAddress = null, professionOid = null)
        val res = OpaGateEnforcer.enforce(null, input, cfg, log)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Skip>()
      }

      "null httpClient with failClosed=true returns Error" {
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = emptyList(),
                audiences = null,
                ipAddress = null,
                professionOid = null,
            )
        val fc = cfg.copy(failClosed = true)
        val res = OpaGateEnforcer.enforce(null, input, fc, log)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Error>()
      }

      "null httpClient with failClosed=false returns Allow" {
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = emptyList(),
                audiences = null,
                ipAddress = null,
                professionOid = null,
            )
        val fo = cfg.copy(failClosed = false)
        val res = OpaGateEnforcer.enforce(null, input, fo, log)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      }

      "Decision.Allow maps to Outcome.Allow" {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = listOf("s1"),
                audiences = listOf("aud1"),
                ipAddress = "127.0.0.1",
                professionOid = "1.2.3",
            )
        mockkObject(OpaDecisionClient)
        try {
          every { OpaDecisionClient.evaluate(any(), any(), any(), any()) } returns Decision.Allow()
          val res = OpaGateEnforcer.enforce(httpClient, input, cfg, log)
          res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        } finally {
          unmockkObject(OpaDecisionClient)
        }
      }

      "Decision.Deny maps to Outcome.Deny" {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = listOf("s1"),
                audiences = listOf("aud1"),
                ipAddress = "127.0.0.1",
                professionOid = "1.2.3",
            )
        mockkObject(OpaDecisionClient)
        try {
          every { OpaDecisionClient.evaluate(any(), any(), any(), any()) } returns Decision.Deny(listOf("x"))
          val res = OpaGateEnforcer.enforce(httpClient, input, cfg, log)
          res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Deny>()
        } finally {
          unmockkObject(OpaDecisionClient)
        }
      }

      "Decision.Error maps per failClosed (true->Error, false->Allow)" {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = listOf("s1"),
                audiences = listOf("aud1"),
                ipAddress = "127.0.0.1",
                professionOid = "1.2.3",
            )
        mockkObject(OpaDecisionClient)
        try {
          every { OpaDecisionClient.evaluate(any(), any(), any(), any()) } returns Decision.Error()

          val resClosed = OpaGateEnforcer.enforce(httpClient, input, cfg.copy(failClosed = true), log)
          resClosed.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Error>()

          val resOpen = OpaGateEnforcer.enforce(httpClient, input, cfg.copy(failClosed = false), log)
          resOpen.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        } finally {
          unmockkObject(OpaDecisionClient)
        }
      }

      "Decision.Allow with TTL maps TTLs to Outcome.Allow" {
        val httpClient = mockk<CloseableHttpClient>(relaxed = true)
        val input =
            OpaGateInput(
                grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
                scopes = listOf("s1"),
                audiences = listOf("aud1"),
                ipAddress = "127.0.0.1",
                professionOid = "1.2.3",
            )
        mockkObject(OpaDecisionClient)
        try {
          every { OpaDecisionClient.evaluate(any(), any(), any(), any()) } returns Decision.Allow(111, 222)
          val res = OpaGateEnforcer.enforce(httpClient, input, cfg, log)
          res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
          assertEquals(111, res.accessTokenTtl)
          assertEquals(222, res.refreshTokenTtl)
        } finally {
          unmockkObject(OpaDecisionClient)
        }
      }
    })
