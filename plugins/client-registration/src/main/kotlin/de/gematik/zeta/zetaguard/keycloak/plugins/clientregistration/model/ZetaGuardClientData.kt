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

import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.FetchType
import jakarta.persistence.Index
import jakarta.persistence.JoinColumn
import jakarta.persistence.ManyToOne
import jakarta.persistence.NamedQueries
import jakarta.persistence.NamedQuery
import jakarta.persistence.Table
import java.time.LocalDateTime

const val TABLE_NAME_CLIENT_DATA = "ZETA_CLIENT_DATA"

/**
 * Query to find IDs of [ZetaGuardClientData] records that have expired.
 *
 * Parameters:
 * - `state`: The [ClientAttestationState] to filter by.
 * - `expirationTime`: The threshold [LocalDateTime] for expiration. Records with `lastAccess` older than this time are returned.
 *
 * Returns: List of client IDs sorted by their `lastAccess` in ascending order.
 */
const val FIND_EXPIRED_CLIENT_DATA = "ZetaGuardClientData.findExpiredClientData"

/**
 * Query to find IDs of all [ZetaGuardClientData] records associated with a specific user.
 *
 * Parameters:
 * - `userName`: The ID (username) of the associated [ZetaGuardUserData].
 *
 * Returns: List of client IDs sorted by their `lastAccess` in ascending order (oldest first).
 */
const val FIND_OLDEST_CLIENTS = "ZetaGuardClientData.findOldestClients"

const val DELETE_CLIENT_DATA = "ZetaGuardClientData.DELETE_CLIENT_DATA"

const val JOIN_COLUMN_USER = "USER_ID"

private const val COLUMN_ATTESTATION_STATE = "ATTESTATION_STATE"
private const val COLUMN_CLIENT_AUTH_METHOD = "CLIENT_AUTH_METHOD"
private const val COLUMN_CLIENT_REGISTRATION_STATUS = "CLIENT_REGISTRATION_STATUS"

/** Store client-related data. */
@Suppress("KotlinRedundantDefaultConstructorJpaCompilerPluginInspection")
@Entity
@Table(
    name = TABLE_NAME_CLIENT_DATA,
    indexes = [
      Index(name = "IDX_USER", columnList = JOIN_COLUMN_USER),
      Index(name = "IDX_CLIENT_EXPIRATION", columnList = "$COLUMN_ATTESTATION_STATE, $COLUMN_LAST_ACCESS"),
      Index(name = "IDX_OLDEST_CLIENT", columnList = COLUMN_LAST_ACCESS)
    ]
)
@NamedQueries(
    value =
        [
          NamedQuery(
              name = FIND_EXPIRED_CLIENT_DATA,
              query =
                  """
    SELECT c.id FROM ZetaGuardClientData c 
    WHERE c.attestationState = :state
    AND c.lastAccess < :expirationTime
    ORDER BY c.lastAccess ASC
    """,
              resultClass = String::class,
          ),
          NamedQuery(
              name = FIND_OLDEST_CLIENTS,
              query =
                  """
    SELECT c.id FROM ZetaGuardClientData c
    WHERE c.userData.id = :userName
    ORDER BY c.lastAccess ASC
    """,
              resultClass = String::class,
          ),
          NamedQuery(name = DELETE_CLIENT_DATA, query = """DELETE FROM ZetaGuardClientData c WHERE c.id = :clientId"""),
        ]
)
class ZetaGuardClientData(clientId: String, createdAt: LocalDateTime, lastAccess: LocalDateTime) : AbstractData(clientId, createdAt, lastAccess) {
  @ManyToOne(fetch = FetchType.LAZY) @JoinColumn(name = JOIN_COLUMN_USER) //
  var userData: ZetaGuardUserData? = null

  @Enumerated(EnumType.STRING)
  @Column(name = COLUMN_ATTESTATION_STATE, nullable = false) //
  var attestationState: ClientAttestationState = ClientAttestationState.INVALID

  @Enumerated(EnumType.STRING)
  @Column(name = COLUMN_CLIENT_AUTH_METHOD, nullable = false)
  var clientAuthMethod: ClientAuthMethod = ClientAuthMethod.SMC_B

  @Enumerated(EnumType.STRING)
  @Column(name = COLUMN_CLIENT_REGISTRATION_STATUS, nullable = true, length = 32)
  var registrationStatus: ClientRegistrationStatus? = null

  // JPA requires a no-arg constructor for entity classes
  @Suppress("unused")
  constructor() : this("", currentTime(), currentTime())
}
