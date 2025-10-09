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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents

import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLog
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService.Companion.GENESIS_PREVIOUS_HASH
import io.kotest.matchers.shouldBe
import java.time.Instant

class AdminEventLoggerTest : AbstractAdminEventLoggerTest() {
    init {
        context("AdminEventLogger") {
            test("basic persistence") {
                val adminEventLog =
                    AdminEventLog(
                        createdAt = Instant.now(),
                        event = """{"event":"test_event"}""",
                        previousHash = "previousHash123",
                        currentHash = "currentHash123",
                    )

                adminEventLogStorageService.saveAdminEventLog(adminEventLog)
                newTransaction()

                val logs = adminEventLogStorageService.findAll()

                logs.size shouldBe 1

                val log = logs.first()
                log.currentHash shouldBe "currentHash123"

                adminEventLogStorageService.previousHash() shouldBe log.currentHash
            }

            test("Hash chain persistence") {
                adminEventLogStorageService.findAll() shouldBe emptyList()
                adminEventLogStorageService.previousHash() shouldBe GENESIS_PREVIOUS_HASH

                eventLogger.onEvent(adminEvent1, true)

                val logs1 = adminEventLogStorageService.findAll()
                logs1.size shouldBe 1

                val log1 = logs1.first()
                log1.previousHash shouldBe GENESIS_PREVIOUS_HASH

                adminEventLogStorageService.previousHash() shouldBe log1.currentHash

                eventLogger.onEvent(adminEvent2, true)

                val logs2 = adminEventLogStorageService.findAll()
                logs2.size shouldBe 2
                logs2.first() shouldBe log1

                val log2 = logs2.second()
                log2.previousHash shouldBe log1.currentHash
            }
        }
    }
}
