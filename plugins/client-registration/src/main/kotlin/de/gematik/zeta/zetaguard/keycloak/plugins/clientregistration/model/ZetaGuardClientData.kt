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

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.clientregistration.AttestationType
import de.gematik.zeta.zetaguard.keycloak.commons.opa.toOpaDeviceInfo
import de.gematik.zeta.zetaguard.keycloak.commons.secondsToLocalDateTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.currentTime
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAttestationState
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientAuthMethod
import de.gematik.zeta.zetaguard.keycloak.commons.server.ClientRegistrationStatus
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
const val COUNT_CLIENTS = "ZetaGuardClientData.countClients"

const val FIND_SEKIDP_CLIENT_IDS = "ZetaGuardClientData.findSekIdpClientIds"

/**
 * Query to find the owner of a [ZetaGuardClientData] record without loading it.
 *
 * Parameters:
 * - `clientId`: The ID (client_id) of the client.
 *
 * Returns: The ID (username) of the associated [ZetaGuardUserData]; no result if the client is gone or not bound to a user.
 */
const val FIND_CLIENT_OWNER = "ZetaGuardClientData.findClientOwner"

const val DELETE_CLIENT_DATA = "ZetaGuardClientData.DELETE_CLIENT_DATA"

const val JOIN_COLUMN_USER = "USER_ID"

private const val COLUMN_ATTESTATION_STATE = "ATTESTATION_STATE"
private const val COLUMN_ATTESTATION_TYPE = "ATTESTATION_TYPE"
private const val COLUMN_CLIENT_AUTH_METHOD = "CLIENT_AUTH_METHOD"
private const val COLUMN_CLIENT_REGISTRATION_STATUS = "CLIENT_REGISTRATION_STATUS"
private const val COLUMN_PLATFORM = "PLATFORM"
private const val COLUMN_PRODUCT_ID = "PRODUCT_ID"
private const val COLUMN_PRODUCT_VERSION = "PRODUCT_VERSION"
private const val COLUMN_OS = "OS"
private const val COLUMN_OS_VERSION = "OS_VERSION"
private const val COLUMN_DEVICE_MODEL = "DEVICE_MODEL"
private const val COLUMN_ATTESTATION_TIMESTAMP = "ATTESTATION_TIMESTAMP"
private const val COLUMN_SESSION_DATA = "SESSION_DATA"
private const val COLUMN_SESSION_UPDATED_AT = "SESSION_UPDATED_AT"
private const val SESSION_DATA_MAX_LENGTH = 65_535

/** Store client-related data. */
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
          NamedQuery(
              name = COUNT_CLIENTS,
              query = """SELECT COUNT(c) FROM ZetaGuardClientData c WHERE c.userData.id = :userName AND c.id <> :clientId""",
              resultClass = Long::class,
          ),
          NamedQuery(name = DELETE_CLIENT_DATA, query = """DELETE FROM ZetaGuardClientData c WHERE c.id = :clientId"""),
          NamedQuery(
              name = FIND_SEKIDP_CLIENT_IDS,
              query = """SELECT c.id FROM ZetaGuardClientData c WHERE c.clientAuthMethod = :authMethod""",
              resultClass = String::class,
          ),
          NamedQuery(
              name = FIND_CLIENT_OWNER,
              query = """SELECT c.userData.id FROM ZetaGuardClientData c WHERE c.id = :clientId""",
              resultClass = String::class,
          ),
        ]
)
// No vals: all-open doesn't touch backing fields, and Hibernate's enhancer skips lazy-load interception for final fields.
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

  @Enumerated(EnumType.STRING)
  @Column(name = COLUMN_ATTESTATION_TYPE, nullable = true)
  var attestationType: AttestationType? = null

  // Client data according to policy-engine-client-data.yaml, https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26585
  @Column(name = COLUMN_PLATFORM, nullable = true, length = 20) //
  var platform: String? = null

  @Column(name = COLUMN_PRODUCT_ID, nullable = true) //
  var productId: String? = null

  @Column(name = COLUMN_PRODUCT_VERSION, nullable = true) //
  var productVersion: String? = null

  @Column(name = COLUMN_OS, nullable = true) //
  var os: String? = null

  @Column(name = COLUMN_OS_VERSION, nullable = true) //
  var osVersion: String? = null

  @Column(name = COLUMN_DEVICE_MODEL, nullable = true) //
  var deviceModel: String? = null

  @Column(name = COLUMN_ATTESTATION_TIMESTAMP, nullable = true) //
  var attestationTimestamp: LocalDateTime? = null

  /**
   * Session data, i.e. the policy engine input (policy-engine-input.yaml) of the last successful authentication or refresh of this client,
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_26586
   *
   * No @Lob: on PostgreSQL Hibernate would store it as a large object and only write its OID into the (CLOB/TEXT) column. The length
   * is only relevant for schema generation in tests, the column is created by Liquibase.
   */
  @Column(name = COLUMN_SESSION_DATA, nullable = true, length = SESSION_DATA_MAX_LENGTH) //
  var sessionData: String? = null

  @Column(name = COLUMN_SESSION_UPDATED_AT, nullable = true) //
  var sessionUpdatedAt: LocalDateTime? = null

  /** Take over the client data from the (verified) client statement of the client assertion */
  fun updateFrom(statement: ClientStatementData) {
    val deviceInfo = statement.posture.toOpaDeviceInfo()

    platform = statement.platform.value
    productId = statement.posture.productId
    productVersion = statement.posture.productVersion
    os = deviceInfo.os
    osVersion = deviceInfo.osVersion
    deviceModel = deviceInfo.deviceModel
    attestationTimestamp = statement.attestationTimestamp.secondsToLocalDateTime()
  }

  /** Store the policy engine input sent to OPA for a successful authentication or refresh */
  fun storeSessionData(opaInput: String) {
    sessionData = opaInput
    sessionUpdatedAt = currentTime()
  }
}
