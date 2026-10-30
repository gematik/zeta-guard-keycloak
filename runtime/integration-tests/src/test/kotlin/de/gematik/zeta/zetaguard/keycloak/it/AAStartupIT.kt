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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_SPREE_INTEGRITY_ENABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.spree.keycloak.commons.configuration.LOG_STATUS_RUNNING
import de.spree.keycloak.commons.configuration.SystemStatus
import io.kotest.core.spec.Order
import io.kotest.core.spec.style.FunSpec
import io.kotest.matchers.shouldBe
import java.io.File
import java.lang.System.getenv
import kotlin.system.exitProcess

/** First "test" that starts Docker compose for all consecutive tests */
@Order(0)
class AAStartupIT : FunSpec() {
  private val itProviderEnabled = (getenv(ENV_SPREE_INTEGRITY_ENABLED) ?: "false").toBoolean()
  var running = false

  init {
    beforeSpec { Docker.start() }

    test("Check for Spree integrity provider") {
      if (itProviderEnabled) {
        var attempts = 0
        logger.info("⏳ Waiting for system status »${SystemStatus.RUNNING}« of Spree integrity provider...")

        while (attempts++ < 10 && !running) {
          Thread.sleep(5000)
          val logFile = File("target/log/keycloak.log")

          logFile.exists() shouldBe true

          println("Checking log file for status message »$LOG_STATUS_RUNNING« ...")

          logFile.bufferedReader().use { reader ->
            var line: String? = null

            do {
              line = reader.readLine()
              running = line?.contains(LOG_STATUS_RUNNING) ?: false
            } while (line != null && !running)
          }
        }

        if (!running) {
          logger.fatal("💣 Spree integrity provider still not running! EXITING.")
          Docker.stop()
          exitProcess(1)
        }
      } else {
        logger.info("⚠️ Spree integrity provider is disabled, skipping checks!")
      }
    }
  }
}
