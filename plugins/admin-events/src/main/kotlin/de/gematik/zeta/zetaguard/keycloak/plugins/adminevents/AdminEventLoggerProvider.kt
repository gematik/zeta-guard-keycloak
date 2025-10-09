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
import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService
import java.time.Instant
import org.jboss.logging.Logger
import org.keycloak.events.Event
import org.keycloak.events.EventListenerProvider
import org.keycloak.events.admin.AdminEvent
import org.keycloak.jose.jws.crypto.HashUtils.sha256UrlEncodedHash
import org.keycloak.util.JsonSerialization

class AdminEventLoggerProvider(private val adminEventLogService: AdminEventLogStorageService) :
    EventListenerProvider {
    private val log: Logger = Logger.getLogger(AdminEventLoggerProvider::class.java)

    override fun onEvent(event: Event) {}

    /** Handles admin events and logs them to the database. */
    override fun onEvent(adminEvent: AdminEvent, includeRepresentation: Boolean) {
        log.infof(
            "Admin Event Occurred: realm=%s, operationType=%s, resourceType=%s, resourcePath=%s",
            adminEvent.realmName,
            adminEvent.operationType,
            adminEvent.resourceType,
            adminEvent.resourcePath,
        )

        if (includeRepresentation) {
            log.debugf("Admin Event Representation: %s", adminEvent.representation)
        }

        val json = JsonSerialization.writeValueAsString(adminEvent)
        val previousHash = adminEventLogService.previousHash()
        val createdAt = Instant.ofEpochMilli(adminEvent.time)
        val currentHash = calculateHash(json, createdAt, previousHash)

        adminEventLogService.saveAdminEventLog(
            AdminEventLog(
                event = json,
                createdAt = createdAt,
                previousHash = previousHash,
                currentHash = currentHash,
            )
        )
    }

    override fun close() {
        // No-op
    }

    companion object {
        /**
         * Calculates a SHA-256 hash for the given event data.
         *
         * @param json The JSON representation of the event.
         * @param timestamp The timestamp of the event.
         * @param previousHash The hash of the previous event log entry.
         * @return The calculated hash as a URL-encoded string.
         */
        fun calculateHash(json: String, timestamp: Instant, previousHash: String): String {
            val input = "$timestamp|$previousHash|$json"
            return sha256UrlEncodedHash(input, Charsets.UTF_8)
        }
    }
}
