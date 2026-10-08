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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.commons.KeycloakWebClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_GENESIS_HASH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_HASHING_PEPPER
import de.gematik.zeta.zetaguard.keycloak.commons.server.HASHING_PEPPER
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService.Companion.GENESIS_HASH
import java.io.File
import java.time.Duration
import kotlin.system.exitProcess
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.containers.ComposeContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.containers.wait.strategy.Wait.forHttp

object Docker {
  private var running = false

  internal val log: Logger = LoggerFactory.getLogger(this.javaClass)

  val tracingEnabled: Boolean = System.getProperty("it.tracing", "false").toBoolean()

  private val STARTUP_TIMEOUT = Duration.ofMinutes(10)!! // Gitlab may be veeeeery slow

  private val composeFiles =
      listOfNotNull(
          File("./docker-compose-it.yml"),
          if (tracingEnabled) File("./docker-compose-tracing-it.yml") else null,
      )

  private val docker: ComposeContainer =
      ComposeContainer(composeFiles)
          .withEnv(ENV_GENESIS_HASH, GENESIS_HASH)
          .withEnv(ENV_HASHING_PEPPER, HASHING_PEPPER)
          .withLogConsumer("keycloak", Slf4jLogConsumer(log).withMdc("container", "keycloak"))
          .withLogConsumer("keycloak-db", Slf4jLogConsumer(log).withMdc("container", "keycloak-db"))
          .withLogConsumer("keycloak-config-cli", Slf4jLogConsumer(log).withMdc("container", "keycloak-config-cli"))
          .withExposedService("keycloak", 8080, Wait.forListeningPort().withStartupTimeout(STARTUP_TIMEOUT))
          .withExposedService("keycloak-db", 5432, Wait.forListeningPort())
          .withExposedService("keycloak-config-cli", 0, WaitForTerminationStrategy.withStartupTimeout(Duration.ofSeconds(240)))
          .let { if (tracingEnabled) it.withExposedService("lgtm", 3200, forHttp("/ready").withStartupTimeout(STARTUP_TIMEOUT)) else it }
          .withRemoveVolumes(true)
          .withPull(true)

  val kchost: String by lazy { if (running) docker.getServiceHost("keycloak", 8080) else KeycloakWebClient.kchost }
  val kcport: Int by lazy { if (running) docker.getServicePort("keycloak", 8080) else KeycloakWebClient.kcport }
  val dbhost: String by lazy { if (running) docker.getServiceHost("keycloak-db", 5432) else KeycloakWebClient.dbhost }
  val dbport: Int by lazy { if (running) docker.getServicePort("keycloak-db", 5432) else KeycloakWebClient.dbport }
  val jdbcUrl: String by lazy { "jdbc:postgresql://$dbhost:$dbport/keycloak?ssl=false&user=zeta-guard&password=geheim" }
  val tempoHost: String by lazy { if (running && tracingEnabled) docker.getServiceHost("lgtm", 3200) else "localhost" }
  val tempoPort: Int by lazy { if (running && tracingEnabled) docker.getServicePort("lgtm", 3200) else 3200 }

  fun start() {
    log.info("Starting Docker compose ... (${running()})")

    if (!running && !KeycloakWebClient.remoteHost) {
      try {
        docker.start()
        running = true
      } catch (e: Throwable) {
        log.error("Error starting Docker compose ...", e)
        exitProcess(1)
      }
    }
  }

  fun stop() {
    log.info("Shutdown Docker compose ... (${running()})")

    if (running) {
      try {
        docker.stop()
      } catch (e: Throwable) {
        log.error("Error stopping Docker compose ...", e)
      }

      running = false
    }
  }

  private fun running(): String = if (running) "already running" else "not running"
}
