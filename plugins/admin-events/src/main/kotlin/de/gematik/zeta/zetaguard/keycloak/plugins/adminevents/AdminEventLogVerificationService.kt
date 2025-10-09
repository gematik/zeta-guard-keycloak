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

package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents

import arrow.core.Either
import arrow.core.raise.either
import arrow.core.raise.ensure
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.AdminEventLoggerProvider.Companion.calculateHash
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService.Companion.GENESIS_PREVIOUS_HASH

/** Service for verifying the integrity of the admin event log chain. */
class AdminEventLogVerificationService(
    private val adminEventLogService: AdminEventLogStorageService
) {
    /**
     * Verifies the integrity of the admin event log chain.
     *
     * This method checks that each log entry's previous hash matches the current hash of the
     * previous entry, and that the current hash is correctly calculated based on the event data and
     * timestamp.
     *
     * @return Either a success or a failure indicating the verification result.
     */
    fun verifyChain(): Either<AdminEventLogVerificationFailure, AdminEventLogVerificationSuccess> =
        either {
            val logs = adminEventLogService.findAll()

            if (logs.isEmpty()) {
                return@either AdminEventLogEmpty
            }

            var previousHash = GENESIS_PREVIOUS_HASH

            for (log in logs) {
                ensure(log.previousHash == previousHash) {
                    InvalidPreviousHash(
                        "Invalid previous hash@${log.id}: expected $previousHash but found ${log.previousHash}"
                    )
                }

                val calculatedHash = calculateHash(log.event, log.createdAt, previousHash)

                ensure(log.currentHash == calculatedHash) {
                    InvalidCurrentHash(
                        "Invalid current hash@${log.id}: expected $calculatedHash but found ${log.currentHash}"
                    )
                }

                previousHash = log.currentHash
            }

            AdminEventLogValid
        }
}
