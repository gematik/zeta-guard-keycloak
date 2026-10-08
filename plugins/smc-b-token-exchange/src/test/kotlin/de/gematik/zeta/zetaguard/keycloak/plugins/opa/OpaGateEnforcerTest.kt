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
package de.gematik.zeta.zetaguard.keycloak.plugins.opa

import io.kotest.core.spec.style.StringSpec
import io.kotest.matchers.types.shouldBeInstanceOf
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import java.util.concurrent.Executor
import org.apache.http.impl.client.CloseableHttpClient
import org.junit.jupiter.api.Assertions.assertEquals

class OpaGateEnforcerTest :
  StringSpec({
    val cfg = OPAConfig()
    val httpClient = mockk<CloseableHttpClient>(relaxed = true)

    "authorization_code grant is gated" {
      val input =
          OpaGateInput(
              grantType = "authorization_code",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = "client-id",
              clientPlatform = "apple",
              clientRegistrationTimestamp = 1,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = "Unknown",
              postureType = "apple",
              userIdentifier = "X110123456",
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Allow()
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "returns Skip for non-gated grant type" {
      val input =
          OpaGateInput(
              grantType = "client_credentials",
              scopes = emptyList(),
              audiences = null,
              ipAddress = null,
              userProfessionOid = null,
              clientProductID = null,
              clientProductVersion = null,
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
      res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Skip>()
    }

    "refresh_token grant: Decision.Allow maps to Outcome.Allow" {
      val input =
          OpaGateInput(
              grantType = "refresh_token",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Allow()
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "refresh_token grant: Decision.Deny maps to Outcome.Deny" {
      val input =
          OpaGateInput(
              grantType = "refresh_token",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Deny(listOf("x"))
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Deny>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "refresh_token grant: missing identity claims are passed through as null" {
      val input =
          OpaGateInput(
              grantType = "refresh_token",
              scopes = emptyList(),
              audiences = null,
              ipAddress = null,
              userProfessionOid = null,
              clientProductID = null,
              clientProductVersion = null,
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Allow()
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "refresh_token grant: simulation is also dispatched" {
      val input =
          OpaGateInput(
              grantType = "refresh_token",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      val originalExecutor = OpaGateEnforcer.simulationExecutor
      OpaGateEnforcer.simulationExecutor = Executor { it.run() }
      try {
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) } returns Decision.Allow()
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) } returns Decision.Allow()

        val simCfg = cfg.copy(simulationBaseUrl = "http://opa-simulation:8181")
        val res = OpaGateEnforcer.enforce(httpClient, input, simCfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        verify(exactly = 1) { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) }
        verify(exactly = 1) { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) }
      } finally {
        OpaGateEnforcer.simulationExecutor = originalExecutor
        unmockkObject(OpaDecisionClient)
      }
    }

    "Decision.Allow maps to Outcome.Allow" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Allow()
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "Decision.Deny maps to Outcome.Deny" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Deny(listOf("x"))
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Deny>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "Decision.Error maps to Outcome.Error (fail-closed)" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Error()
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Error>()
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "simulation is called but does not change outcome" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      val originalExecutor = OpaGateEnforcer.simulationExecutor
      OpaGateEnforcer.simulationExecutor = Executor { it.run() }
      try {
        // main OPA allows, simulation denies — outcome must still be Allow
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) } returns Decision.Allow()
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) } returns
            Decision.Deny(listOf("sim-reason"))

        val simCfg = cfg.copy(simulationBaseUrl = "http://opa-simulation:8181")
        val res = OpaGateEnforcer.enforce(httpClient, input, simCfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        verify(exactly = 1) { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) }
        verify(exactly = 1) { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) }
      } finally {
        OpaGateEnforcer.simulationExecutor = originalExecutor
        unmockkObject(OpaDecisionClient)
      }
    }

    "simulation is non-blocking and slow simulation does not delay outcome" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) } returns Decision.Allow()
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) } answers
            {
              Thread.sleep(2_000)
              Decision.Allow()
            }

        val simCfg = cfg.copy(simulationBaseUrl = "http://opa-simulation:8181")
        val start = System.currentTimeMillis()
        val res = OpaGateEnforcer.enforce(httpClient, input, simCfg)
        val elapsed = System.currentTimeMillis() - start

        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        // Active OPA returned immediately; simulation is fire-and-forget so enforce() should not wait 2s.
        assert(elapsed < 1_000) { "enforce() took ${elapsed}ms — simulation is blocking the request thread" }
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }

    "simulation failure does not affect outcome" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      val originalExecutor = OpaGateEnforcer.simulationExecutor
      OpaGateEnforcer.simulationExecutor = Executor { it.run() }
      try {
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa:8181" }, any()) } returns Decision.Allow()
        every { OpaDecisionClient.evaluate(any(), match { it.opaBaseUrl == "http://opa-simulation:8181" }, any()) } throws
            RuntimeException("sim engine on fire")

        val simCfg = cfg.copy(simulationBaseUrl = "http://opa-simulation:8181")
        val res = OpaGateEnforcer.enforce(httpClient, input, simCfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
      } finally {
        OpaGateEnforcer.simulationExecutor = originalExecutor
        unmockkObject(OpaDecisionClient)
      }
    }

    "Decision.Allow with TTL maps TTLs to Outcome.Allow" {
      val input =
          OpaGateInput(
              grantType = "urn:ietf:params:oauth:grant-type:token-exchange",
              scopes = listOf("s1"),
              audiences = listOf("aud1"),
              ipAddress = "127.0.0.1",
              userProfessionOid = "1.2.3",
              clientProductID = "ZETA-Test-Client",
              clientProductVersion = "1.0.0",
              clientId = null,
              clientPlatform = null,
              clientRegistrationTimestamp = null,
              authenticationMethodsReferences = emptyList(),
              authenticationContextClassReference = "abc",
              previousIpAddress = null,
              postureType = null,
              userIdentifier = null,
          )
      mockkObject(OpaDecisionClient)
      try {
        every { OpaDecisionClient.evaluate(any(), any(), any()) } returns Decision.Allow(111, 222)
        val res = OpaGateEnforcer.enforce(httpClient, input, cfg)
        res.shouldBeInstanceOf<OpaGateEnforcer.Outcome.Allow>()
        assertEquals(111, res.accessTokenTtl)
        assertEquals(222, res.refreshTokenTtl)
      } finally {
        unmockkObject(OpaDecisionClient)
      }
    }
  })
