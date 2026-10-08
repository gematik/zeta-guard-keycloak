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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model

import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import jakarta.persistence.CascadeType
import jakarta.persistence.Entity
import jakarta.persistence.Index
import jakarta.persistence.NamedQueries
import jakarta.persistence.NamedQuery
import jakarta.persistence.OneToMany
import jakarta.persistence.Table
import java.time.LocalDateTime

const val TABLE_NAME_USER_DATA = "ZETA_USER_DATA"

/**
 * Query to find IDs of [ZetaGuardUserData] records that have expired and have no associated clients.
 *
 * Parameters:
 * - `expirationTime`: The threshold [LocalDateTime] for expiration. Records with `lastAccess` older than this time are returned.
 *
 * Returns: List of user IDs sorted by their `lastAccess` in descending order.
 */
const val FIND_EXPIRED_USER_DATA = "ZetaGuardUserData.findExpiredUserData"

/** Store user-related data. */
@Suppress("JpaEntityWithValAttributesInspection", "KotlinRedundantDefaultConstructorJpaCompilerPluginInspection")
@Entity
@Table(name = TABLE_NAME_USER_DATA, indexes = [Index(name = "IDX_USER_EXPIATION", columnList = COLUMN_LAST_ACCESS)])
@NamedQueries(
    value =
        [
          NamedQuery(
              name = FIND_EXPIRED_USER_DATA,
              query =
                  """
    SELECT u.id FROM ZetaGuardUserData u
    LEFT JOIN u.clients c
    WHERE u.lastAccess < :expirationTime
    AND c.id IS NULL
    ORDER BY u.lastAccess DESC
    """,
              resultClass = String::class,
          )
        ]
)
class ZetaGuardUserData(userName: String, createdAt: LocalDateTime, lastAccess: LocalDateTime) : AbstractData(userName, createdAt, lastAccess) {
  @OneToMany(cascade = [CascadeType.REMOVE], orphanRemoval = true, mappedBy = "userData") //
  val clients: MutableSet<ZetaGuardClientData> = HashSet()

  // JPA requires a no-arg constructor for entity classes
  @Suppress("unused")
  constructor() : this("", currentTime(), currentTime())
}
