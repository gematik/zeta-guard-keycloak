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

import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import jakarta.ws.rs.core.Response
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.apache.http.impl.client.CloseableHttpClient
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.events.Errors

object OpaGateEnforcer {
  sealed interface Outcome {
    data object Skip : Outcome

    data class Allow(val accessTokenTtl: Int? = null, val refreshTokenTtl: Int? = null) : Outcome

    data class Deny(val error: KeycloakError) : Outcome

    data class Error(val error: KeycloakError) : Outcome
  }

  fun enforce(httpClient: CloseableHttpClient?, opaGateInput: OpaGateInput, opaConfig: OPAConfig, log: Logger): Outcome {
    val grantType = opaGateInput.grantType
    if (!isTokenExchangeGrant(grantType)) return Outcome.Skip

    if (httpClient == null) return handleHttpClientUnavailable(opaConfig, log)

    val payloadJson = buildPayloadJson(opaGateInput)
    log.debugf("🛡 OPA TokenPolicy payload/input -> %s", payloadJson)
    log.debugf("🛡 OPA TokenPolicy decision endpoint -> %s%s", opaConfig.opaBaseUrl, opaConfig.decisionPath)

    val decision = OpaDecisionClient.evaluate(httpClient, opaConfig, payloadJson, log)
    val outcome = mapDecisionToOutcome(decision, opaConfig, log)

    if (opaConfig.simulationBaseUrl.isNotBlank()) submitSimulation(httpClient, opaConfig, payloadJson, log)

    return outcome
  }

  // Fire-and-forget pool for simulation calls — must never block the active OPA decision path. Bounded queue +
  // DiscardOldest sheds load by dropping stale payloads if the simulation engine falls behind.
  internal var simulationExecutor: Executor = createDefaultSimulationExecutor()

  private fun createDefaultSimulationExecutor(): Executor {
    val threadCounter = AtomicLong()
    return ThreadPoolExecutor(
        1,
        2,
        60L,
        TimeUnit.SECONDS,
        LinkedBlockingQueue(16),
        { runnable -> Thread(runnable, "opa-simulation-${threadCounter.incrementAndGet()}").apply { isDaemon = true } },
        ThreadPoolExecutor.DiscardOldestPolicy(),
    )
  }

  private fun submitSimulation(httpClient: CloseableHttpClient, opaConfig: OPAConfig, payloadJson: String, log: Logger) {
    try {
      simulationExecutor.execute { runSimulation(httpClient, opaConfig, payloadJson, log) }
    } catch (e: RejectedExecutionException) {
      log.warnf("🔮 OPA-Sim TokenPolicy submission rejected: %s", e.message)
    }
  }

  private fun policyDenied() = KeycloakError(Errors.ACCESS_DENIED, "policy_denied", Response.Status.FORBIDDEN)

  private fun temporarilyUnavailable() = KeycloakError("temporarily_unavailable", "policy_unavailable", Response.Status.SERVICE_UNAVAILABLE)

  private fun isTokenExchangeGrant(grantType: String?) = TOKEN_EXCHANGE_GRANT_TYPE.equals(grantType, ignoreCase = true)

  private fun handleHttpClientUnavailable(opaConfig: OPAConfig, log: Logger): Outcome {
    log.warnf("🛡 OPA TokenPolicy HttpClient unavailable; failClosed=%s -> %s", opaConfig.failClosed, if (opaConfig.failClosed) "503" else "ALLOW")
    return if (opaConfig.failClosed) Outcome.Error(temporarilyUnavailable()) else Outcome.Allow()
  }

  private fun buildPayloadJson(input: OpaGateInput): String =
      OpaPayloadBuilder.build(
          OpaPayloadBuilder.PayloadParams(
              scopes = input.scopes,
              audiences = input.audiences,
              grantType = input.grantType,
              ipAddress = input.ipAddress,
              professionOid = input.professionOid,
              productId = input.productID,
              productVersion = input.productVersion
          )
      )

  private fun mapDecisionToOutcome(decision: Decision, opaConfig: OPAConfig, log: Logger): Outcome =
      when (decision) {
        is Decision.Allow -> {
          log.infof(
              "🛡 OPA TokenPolicy decision result=true -> ALLOW (access_ttl=%s, refresh_ttl=%s)",
              decision.accessTokenTtl,
              decision.refreshTokenTtl,
          )
          Outcome.Allow(decision.accessTokenTtl, decision.refreshTokenTtl)
        }

        is Decision.Deny -> {
          val reasonsText = formatReasons(decision.reasons)
          log.infof("🛡 OPA TokenPolicy decision result=false -> DENY reasons=%s", reasonsText)
          Outcome.Deny(policyDenied())
        }

        is Decision.Error -> {
          log.warnf("🛡 OPA TokenPolicy: could not obtain decision; failClosed=%s -> %s", opaConfig.failClosed, if (opaConfig.failClosed) "503" else "ALLOW")
          if (opaConfig.failClosed) Outcome.Error(temporarilyUnavailable()) else Outcome.Allow()
        }
      }

  private fun runSimulation(httpClient: CloseableHttpClient, opaConfig: OPAConfig, payloadJson: String, log: Logger) {
    try {
      val simConfig = opaConfig.copy(opaBaseUrl = opaConfig.simulationBaseUrl)
      log.debugf("🔮 OPA-Sim TokenPolicy decision endpoint -> %s%s", simConfig.opaBaseUrl, simConfig.decisionPath)
      val decision = OpaDecisionClient.evaluate(httpClient, simConfig, payloadJson, log)
      logSimDecision(decision, log)
    } catch (e: Exception) {
      log.warnf(e, "🔮 OPA-Sim TokenPolicy unexpected error")
    }
  }

  private fun logSimDecision(decision: Decision, log: Logger) =
      when (decision) {
        is Decision.Allow ->
          log.infof(
              "🔮 OPA-Sim TokenPolicy result=true -> ALLOW (access_ttl=%s, refresh_ttl=%s)",
              decision.accessTokenTtl,
              decision.refreshTokenTtl,
          )
        is Decision.Deny ->
          log.infof(
              "🔮 OPA-Sim TokenPolicy result=false -> DENY reasons=%s",
              formatReasons(decision.reasons),
          )
        is Decision.Error -> log.warnf("🔮 OPA-Sim TokenPolicy error getting decision")
      }

  private fun formatReasons(reasons: List<String>) = if (reasons.isEmpty()) "[]" else reasons.joinToString(prefix = "[", postfix = "]")
}
