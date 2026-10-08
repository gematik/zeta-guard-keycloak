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

import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.spree.keycloak.commons.configuration.LOG_STATE_OPERATIONAL
import de.spree.keycloak.commons.configuration.SystemState
import de.spree.keycloak.commons.integrityProviderEnabled
import io.kotest.core.config.AbstractProjectConfig
import java.io.File
import kotlin.system.exitProcess

private const val OPERATIONAL_POLL_ATTEMPTS = 10
private const val OPERATIONAL_POLL_INTERVAL_MILLIS = 5000L

/**
 * Owns the compose stack for the whole suite. Registered via `kotest.properties`.
 */
class KotestProjectConfig : AbstractProjectConfig() {

  override suspend fun beforeProject() {
    Docker.start()
    awaitIntegrityProvider()
  }

  override suspend fun afterProject() = Docker.stop()

  /**
   * Blocks until the Spree integrity provider reports [SystemState.OPERATIONAL], so no spec runs
   * against a half-ready server
   */
  private fun awaitIntegrityProvider() {
    if (!integrityProviderEnabled) {
      logger.info("⚠️ Spree integrity provider is disabled, skipping checks!")
      return
    }

    logger.info("⏳ Waiting for system state »${SystemState.OPERATIONAL}« of Spree integrity provider...")
    val logFile = File("target/log/keycloak.log")

    repeat(OPERATIONAL_POLL_ATTEMPTS) {
      Thread.sleep(OPERATIONAL_POLL_INTERVAL_MILLIS)

      if (logFile.exists() && logFile.useLines { lines -> lines.any { it.contains(LOG_STATE_OPERATIONAL) } }) {
        return
      }
      logger.info("Checking log file for status message »$LOG_STATE_OPERATIONAL« ...")
    }

    logger.fatal("💣 Spree integrity provider still not running! EXITING.")
    // Stop the stack first: a throw here would leave the containers behind, as afterProject is not
    // guaranteed to run once beforeProject failed.
    Docker.stop()
    exitProcess(1)
  }
}
