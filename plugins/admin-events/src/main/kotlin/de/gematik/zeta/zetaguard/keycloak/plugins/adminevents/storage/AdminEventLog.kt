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
package de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage

import de.gematik.zeta.zetaguard.keycloak.plugins.adminevents.storage.AdminEventLogStorageService.Companion.GENESIS_PREVIOUS_HASH
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.Id
import jakarta.persistence.Lob
import jakarta.persistence.Table
import java.time.Instant
import java.util.Objects
import java.util.UUID
import org.apache.commons.lang3.builder.ToStringBuilder
import org.apache.commons.lang3.builder.ToStringStyle.NO_FIELD_NAMES_STYLE

/**
 * Represents an admin event log entry in the database.
 *
 * @property id The unique identifier of the log entry.
 * @property createdAt The timestamp when the log entry was created.
 * @property event The JSON representation of the admin event.
 * @property previousHash The hash of the previous log entry, used for integrity verification.
 * @property currentHash The hash of the current log entry, calculated from the event data and
 *   timestamp.
 */
@Entity
@Table(name = "admin_event_log")
class AdminEventLog(
    @Id
    @GeneratedValue
    @Column(name = "id", nullable = false, updatable = false)
    val id: UUID? = null,
    @Column(name = "created_at", nullable = false) val createdAt: Instant,
    @Lob @Column(name = "event_data", nullable = false) val event: String,
    @Column(name = "previous_hash", nullable = false, length = 64, unique = true)
    val previousHash: String,
    @Column(name = "current_hash", nullable = false, length = 64, unique = true)
    val currentHash: String,
) {
    // JPA requires a no-arg constructor for entity classes
    @Suppress("unused")
    private constructor() :
        this(null, Instant.now(), "", GENESIS_PREVIOUS_HASH, GENESIS_PREVIOUS_HASH)

    override fun equals(other: Any?): Boolean =
        when {
            this === other -> true

            other?.javaClass != this.javaClass -> false

            else -> this.currentHash == (other as AdminEventLog).currentHash
        }

    override fun hashCode(): Int = Objects.hashCode(currentHash) + javaClass.hashCode()

    override fun toString(): String = ToStringBuilder.reflectionToString(this, NO_FIELD_NAMES_STYLE)
}
