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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.it

import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService.Companion.GENESIS_PREVIOUS_HASH
import java.io.File
import java.time.Duration
import kotlin.system.exitProcess
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testcontainers.containers.ComposeContainer
import org.testcontainers.containers.output.Slf4jLogConsumer
import org.testcontainers.containers.wait.strategy.Wait

object Docker {
  private var running = false

  internal val log: Logger = LoggerFactory.getLogger(this.javaClass)

  private val docker: ComposeContainer =
      ComposeContainer(File("./docker-compose-it.yml"))
          .withEnv("GENESIS_HASH", GENESIS_PREVIOUS_HASH)
          .withLogConsumer("keycloak", Slf4jLogConsumer(log).withMdc("container", "keycloak"))
          .withLogConsumer("keycloak-db", Slf4jLogConsumer(log).withMdc("container", "keycloak-db"))
          .withLogConsumer("keycloak-config-cli", Slf4jLogConsumer(log).withMdc("container", "keycloak-config-cli"))
          .withExposedService("keycloak", 8080, Wait.forListeningPort().withStartupTimeout(Duration.ofSeconds(240)))
          .withExposedService("keycloak-db", 5432, Wait.forListeningPort())
          .withExposedService("keycloak-config-cli", 0, WaitForTerminationStrategy)
          .withRemoveVolumes(true)
          .withPull(true)

  val kchost: String by lazy { if (running) docker.getServiceHost("keycloak", 8080) else "localhost" }
  val kcport: Int by lazy { if (running) docker.getServicePort("keycloak", 8080) else 18080 }
  val dbhost: String by lazy { if (running) docker.getServiceHost("keycloak-db", 5432) else "localhost" }
  val dbport: Int by lazy { if (running) docker.getServicePort("keycloak-db", 5432) else 15432 }
  val jdbcUrl: String by lazy { "jdbc:postgresql://$dbhost:$dbport/keycloak?ssl=false&user=zeta-guard&password=geheim" }

  fun start() {
    log.info("Starting Docker compose ..." + running())

    if (!running) {
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
    log.info("Shutdown Docker compose ..." + running())

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
