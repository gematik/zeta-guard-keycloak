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
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import io.opentelemetry.context.Context.taskWrapping
import jakarta.ws.rs.core.Response
import java.util.concurrent.Executor
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong
import org.apache.http.impl.client.CloseableHttpClient
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants.AUTHORIZATION_CODE
import org.keycloak.OAuth2Constants.REFRESH_TOKEN
import org.keycloak.OAuth2Constants.TOKEN_EXCHANGE_GRANT_TYPE
import org.keycloak.events.Errors

object OpaGateEnforcer {
  sealed interface Outcome {
    data object Skip : Outcome

    data class Allow(val accessTokenTtl: Int? = null, val refreshTokenTtl: Int? = null) : Outcome

    data class Deny(val error: KeycloakError) : Outcome

    data class Error(val error: KeycloakError) : Outcome
  }

  fun enforce(httpClient: CloseableHttpClient, opaGateInput: OpaGateInput, opaConfig: OPAConfig): Outcome {
    val grantType = opaGateInput.grantType

    if (!isGatedGrant(grantType)) {
      return Outcome.Skip
    }

    val payloadJson = buildPayloadJson(opaGateInput)
    logger.debugf("🛡 OPA TokenPolicy payload/input -> %s", payloadJson)
    logger.debugf("🛡 OPA TokenPolicy decision endpoint -> %s%s", opaConfig.opaBaseUrl, opaConfig.decisionPath)

    val decision = OpaDecisionClient.evaluate(httpClient, opaConfig, payloadJson)
    val outcome = mapDecisionToOutcome(decision)

    if (opaConfig.simulationBaseUrl.isNotBlank()) submitSimulation(httpClient, opaConfig, payloadJson)

    return outcome
  }

  // Fire-and-forget pool for simulation calls — must never block the active OPA decision path.
  // Bounded queue +
  // DiscardOldest sheds load by dropping stale payloads if the simulation engine falls behind.
  internal var simulationExecutor: Executor = taskWrapping(createDefaultSimulationExecutor())

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

  private fun submitSimulation(httpClient: CloseableHttpClient, opaConfig: OPAConfig, payloadJson: String) {
    try {
      simulationExecutor.execute { runSimulation(httpClient, opaConfig, payloadJson) }
    } catch (e: RejectedExecutionException) {
      logger.warnf("🔮 OPA-Sim TokenPolicy submission rejected: %s", e.message)
    }
  }

  private fun policyDenied() = KeycloakError(Errors.ACCESS_DENIED, "policy_denied", Response.Status.FORBIDDEN)

  private fun temporarilyUnavailable() = KeycloakError("temporarily_unavailable", "policy_unavailable", Response.Status.SERVICE_UNAVAILABLE)

  private fun isGatedGrant(grantType: String?) =
      TOKEN_EXCHANGE_GRANT_TYPE.equals(grantType, ignoreCase = true) ||
          REFRESH_TOKEN.equals(grantType, ignoreCase = true) ||
          AUTHORIZATION_CODE.equals(grantType, ignoreCase = true)

  private fun buildPayloadJson(input: OpaGateInput): String = OpaPayloadBuilder.build(OpaPayloadBuilder.payloadParamsFromInput(input))

  private fun mapDecisionToOutcome(decision: Decision): Outcome =
      when (decision) {
        is Decision.Allow -> {
          logger.infof(
              "🛡 OPA TokenPolicy decision result=true -> ALLOW (access_ttl=%s, refresh_ttl=%s)",
              decision.accessTokenTtl,
              decision.refreshTokenTtl,
          )
          Outcome.Allow(decision.accessTokenTtl, decision.refreshTokenTtl)
        }

        is Decision.Deny -> {
          val reasonsText = formatReasons(decision.reasons)
          logger.infof("🛡 OPA TokenPolicy decision result=false -> DENY reasons=%s", reasonsText)
          Outcome.Deny(policyDenied())
        }

        is Decision.Error -> {
          logger.warn("🛡 OPA TokenPolicy: could not obtain decision -> 503")
          Outcome.Error(temporarilyUnavailable())
        }
      }

  private fun runSimulation(httpClient: CloseableHttpClient, opaConfig: OPAConfig, payloadJson: String) {
    try {
      val simConfig = opaConfig.copy(opaBaseUrl = opaConfig.simulationBaseUrl)
      logger.debugf("🔮 OPA-Sim TokenPolicy decision endpoint -> %s%s", simConfig.opaBaseUrl, simConfig.decisionPath)
      val decision = OpaDecisionClient.evaluate(httpClient, simConfig, payloadJson)
      logSimDecision(decision, logger)
    } catch (e: Exception) {
      logger.warnf(e, "🔮 OPA-Sim TokenPolicy unexpected error")
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

        is Decision.Deny -> log.infof("🔮 OPA-Sim TokenPolicy result=false -> DENY reasons=%s", formatReasons(decision.reasons))
        is Decision.Error -> log.warnf("🔮 OPA-Sim TokenPolicy error getting decision")
      }

  private fun formatReasons(reasons: List<String>) = if (reasons.isEmpty()) "[]" else reasons.joinToString(prefix = "[", postfix = "]")
}
