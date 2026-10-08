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
package de.gematik.zeta.zetaguard.keycloak.loadtest

import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityProviderUtil.setupSecurityProviders
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.DurationUnit
import kotlin.time.TimedValue
import kotlin.time.measureTime
import kotlin.time.measureTimedValue
import kotlin.time.toDuration
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import org.keycloak.common.crypto.CryptoIntegration
import org.keycloak.representations.AccessTokenResponse
import org.slf4j.Logger
import org.slf4j.LoggerFactory

const val JOB_COUNT = 100

object LoadTestRunner {
  internal val logger: Logger = LoggerFactory.getLogger(this.javaClass)

  @JvmStatic
  fun main(args: Array<String>) = runBlocking {
    setupSecurityProviders()
    CryptoIntegration.init(LoadTestRunner::class.java.getClassLoader())
    logger.info("Starting load test with $JOB_COUNT concurrent requests...")
    var totalHttpRequests = 0
    var delaysTotal = 0.toDuration(DurationUnit.SECONDS)
    val delayAfterRefresh = 1.toDuration(DurationUnit.SECONDS)
    var liveJobs = JOB_COUNT

    val time = measureTime {
      val jobs =
          List(JOB_COUNT) { i ->
            val id = "%03d".format(i + 1)
            var httpRequests = 0

            async(Dispatchers.IO) {
              try {
                val job = LoadTest(i + 1)
                val initialDelay = Random.nextInt(1, 10).toDuration(DurationUnit.SECONDS)

                delay(initialDelay)
                delaysTotal = delaysTotal.plus(initialDelay)

                (1..Random.nextInt(5, 10)).forEach { _ ->
                  val registrationTime = measureTimedValue { job.registerClient() }
                  logger.info("$id: Registration time: ${registrationTime.toSeconds()}")
                  httpRequests++

                  // Execute token exchange several times + refresh token
                  (1..Random.nextInt(5, 10)).forEach { _ ->
                    val tokenExchangeTime = measureTimedValue { job.tokenExchange(registrationTime.value) }
                    logger.info("$id: Token exchange: ${tokenExchangeTime.toSeconds()}")
                    httpRequests += 2
                    var accessTokenResponse: AccessTokenResponse = tokenExchangeTime.value

                    (1..Random.nextInt(5, 10)).forEach { _ ->
                      val refreshTokenTime = measureTimedValue { job.refreshToken(accessTokenResponse, registrationTime.value.clientId) }
                      accessTokenResponse = refreshTokenTime.value
                      httpRequests += 2
                      logger.info("$id: Refresh token: ${refreshTokenTime.toSeconds()}")
                      delay(delayAfterRefresh)
                      delaysTotal = delaysTotal.plus(delayAfterRefresh)
                    }
                  }
                }
              } catch (e: Exception) {
                logger.error("$id: Request failed", e)
              }

              liveJobs--
              totalHttpRequests += httpRequests
              logger.info("$id: Finished after executing $httpRequests requests... Live jobs: $liveJobs")
            }
          }
      // Wait for all requests to complete
      jobs.awaitAll()
    }

    val settledTime = time.minus(delaysTotal)
    logger.info("Finished load test within ${settledTime.toSeconds()} (${time.toSeconds()}) executing $totalHttpRequests requests")
    logger.info("Delays: ${delaysTotal.toSeconds()}")
  }

  private fun TimedValue<*>.toSeconds(): String = duration.toSeconds()

  private fun Duration.toSeconds(): String = toString(DurationUnit.SECONDS, 2)
}
