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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import arrow.core.Either
import arrow.core.flatMap
import arrow.core.getOrElse
import de.gematik.zeta.zetaguard.keycloak.commons.events.ClientRemovalReason
import de.gematik.zeta.zetaguard.keycloak.commons.events.fireClientRemoved
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REALM_CLIENT_JOB_DISABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_IDLE_CLIENT_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_IDLE_USER_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.UserRole
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.positiveIntFromEnv
import de.gematik.zeta.zetaguard.keycloak.commons.server.safeGetenv
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDateTimePeriod
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.jpa.realmProvider
import de.gematik.zeta.zetaguard.keycloak.jpa.userProvider
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardClientRegistrationPolicyFactory.Companion.logger
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel

/**
 * Configurable "Time-to-live" (TTL) of a client registration in the pending state.
 *
 * It is specified in ISO-8601 format and defaults to "PT5M" (5 minutes).
 */
private val CLIENT_REGISTRATION_TTL = safeGetenv(ENV_CLIENT_REGISTRATION_TTL, "PT5M")

/**
 * Configurable "Time-to-live" (TTL) of active clients before they are considered idle/expired.
 *
 * It is specified in ISO-8601 format and defaults to "P1Y" (1 year).
 */
private val IDLE_CLIENT_TTL = safeGetenv(ENV_IDLE_CLIENT_TTL, "P1Y")

/**
 * Configurable "Time-to-live" (TTL) of users before they are considered idle/expired.
 *
 * It is specified in ISO-8601 format and defaults to "P1Y" (1 year).
 */
private val IDLE_USER_TTL = safeGetenv(ENV_IDLE_USER_TTL, "P1Y")

/** Default of [EXPIRATION_BATCH_SIZE]. */
private const val DEFAULT_EXPIRATION_BATCH_SIZE = 500

/**
 * Maximum number of expired client registrations, clients and users removed per batch, i.e. per transaction of the expiration job.
 *
 * Defaults to [DEFAULT_EXPIRATION_BATCH_SIZE]. Bounds the memory and the duration of a transaction, however large the backlog of expired clients is.
 */
private val EXPIRATION_BATCH_SIZE = positiveIntFromEnv(ENV_CLIENT_REGISTRATION_EXPIRATION_BATCH_SIZE, DEFAULT_EXPIRATION_BATCH_SIZE)

private val clientTTL = IDLE_CLIENT_TTL.toDateTimePeriod()

private val userTTL = IDLE_USER_TTL.toDateTimePeriod()

private val clientRegistrationTTL = CLIENT_REGISTRATION_TTL.toDateTimePeriod()

/** Why a client registration is removed, used as log label. */
private enum class RemovalCause(val label: String, val reason: ClientRemovalReason) {
  /** Idle beyond the configured TTL (A_28808). */
  EXPIRED("expired", ClientRemovalReason.EXPIRED),

  /** Maximum number of clients per user exceeded (A_25748-02). */
  EVICTED("evicted", ClientRemovalReason.MAX_CLIENTS_EXCEEDED),
}

/**
 * Expired, i.e., unused clients will be deleted after a configurable amount of time.
 *
 * For details, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28808
 *
 * @param session The Keycloak session to interact with Keycloak providers and models.
 */
class ZetaGuardExpirationService(private val session: KeycloakSession) {
  private val expirationService: ZetaGuardClientExpirationDao by lazy { ZetaGuardClientExpirationDao(DefaultEMCreator(session)) }

  private val dataService: ZetaGuardDataService by lazy { ZetaGuardDataService(DefaultEMCreator(session)) }

  /**
   * Removes the "oldest" client of a user, i.e. the client with the earliest last access time.
   *
   * Called when the maximum number of clients per user is exceeded, see
   * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_25748-02
   *
   * @return true upon success
   */
  fun removeOldestClient(userName: String): Boolean {
    val realm = session.realms().getRealmByName(ZETA_REALM)
    val clientId = expirationService.findOldestClients(userName).firstOrNull() ?: return false
    // Not removed means the expiration job has removed it concurrently, which serves the caller just as well
    deleteAndRemoveAllExpiredClients(session, realm, setOf(clientId), cause = RemovalCause.EVICTED).getOrElse {
      logger.error("⚠️ Failed to remove oldest client »$clientId« for user »$userName«", it)
      return false
    }

    return true
  }

  /**
   * Executes the expiration check and deletion logic for both clients and users, for at most [batchSize] clients and [batchSize] users.
   *
   * What is left over is removed by the next run. Everything a run loads stays in its session until the transaction ends, so the batch size
   * bounds the memory and the duration of the transaction, however large the backlog of expired clients is.
   *
   * The job is skipped if the target realm [ZETA_REALM] is not found, or if it is temporarily disabled via the realm attribute
   * [ATTRIBUTE_REALM_CLIENT_JOB_DISABLED].
   *
   * @param batchSize The maximum number of expired clients and of expired users to remove.
   * @return The number of expired clients and users successfully removed.
   */
  fun runExpiration(batchSize: Int = EXPIRATION_BATCH_SIZE): Pair<Int, Int> {
    logger.info("⏳ Checking for idle client registrations (TTL: $clientRegistrationTTL), clients (TTL: $clientTTL) and users (TTL: $userTTL)")

    val realm = session.realms().getRealmByName(ZETA_REALM)

    if (realm != null) {
      // Ability to disable cleanup job temporarily via realm attribute
      val jobDisabled = "true" == realm.attributes[ATTRIBUTE_REALM_CLIENT_JOB_DISABLED]

      if (jobDisabled) {
        logger.info("⏳ Client expiration job is disabled for realm »$ZETA_REALM«, skipping checks")
      } else {
        val expiredClientsIds =
            findExpiredClientRegistrations(batchSize)
                .onRight { clientIds ->
                  clientIds.forEach {
                    SecurityEventLogger.logClientRegistrationFail(
                        clientId = it,
                        reason = "registration_expired",
                        userRole = UserRole.Unbekannt,
                    )
                  }
                }
                .flatMap { findExpiredClients(it, batchSize) }
                .flatMap { deleteAndRemoveAllExpiredClients(session, realm, it) }
                .getOrElse {
                  logger.error("⚠️ Failed to expire clients", it)
                  throw it
                }

        val expiredUserIds =
            findExpiredUsers(batchSize)
                .flatMap { removeExpiredUsers(session, realm, it) }
                .getOrElse {
                  logger.error("⚠️ Failed to expire users", it)
                  throw it
                }

        return expiredClientsIds.size to expiredUserIds.size
      }
    } else { // May happen at startup
      logger.warn("⚠️ Realm »$ZETA_REALM« not found, skipping client expiration checks")
    }

    return 0 to 0
  }

  /**
   * Removes the specified expired users from Keycloak and deletes their associated database records.
   *
   * @param session The active KeycloakSession.
   * @param realm The realm model where the users belong.
   * @param userNames List of user names of the expired users to delete.
   * @return An [Either] containing a [Throwable] if the removal failed, or list of user ids on success.
   */
  private fun removeExpiredUsers(session: KeycloakSession, realm: RealmModel, userNames: List<String>) =
      Either.catch {
        val userProvider = session.userProvider

        userNames.forEach {
          logger.info("🗑️ Removing expired user with id »$it«")
          // The Keycloak user may be gone already, e.g. removed in the admin console. Its data is removed all the same, otherwise the
          // expired entry could never be removed and would fail every time.
          userProvider.getUserByUsername(realm, it)?.let { userModel -> userProvider.removeUser(realm, userModel) }
          dataService.deleteUserData(it)
        }

        userNames
      }

  /**
   * Removes the specified expired clients from Keycloak and deletes their associated database records.
   *
   * @param session The active KeycloakSession.
   * @param realm The realm model where the clients belong.
   * @param expiredClientIds Set of client IDs of the expired clients to delete.
   * @param cause Why the clients are removed, only used for logging.
   * The client data is deleted first, and only if this call actually deleted it the Keycloak client is removed as well.
   * Both the expiration job and the eviction of the oldest client end up here, possibly for the same client at the same
   * time: deleting in the same order lets the second one wait for the row lock of the first and then skip the client,
   * instead of failing on a row deleted in between or deadlocking on the two rows locked in opposite order.
   *
   * @return An [Either] containing a [Throwable] if the removal failed, or the set of client IDs deleted by this call.
   */
  private fun deleteAndRemoveAllExpiredClients(
      session: KeycloakSession,
      realm: RealmModel,
      expiredClientIds: Set<String>,
      cause: RemovalCause = RemovalCause.EXPIRED,
  ) = Either.catch {
    val realmProvider = session.realmProvider

    expiredClientIds.filterTo(mutableSetOf()) { clientId ->
      // ZETA client data is keyed by the public client_id; read before the deletion, which takes the owner with it.
      // session.userProvider like in removeExpiredUsers: session.users() needs a realm-bound session, the job's is not
      val kclient = realm.getClientByClientId(clientId)
      val owner = dataService.findClientOwner(clientId)?.let { userName -> session.userProvider.getUserByUsername(realm, userName) }

      if (dataService.deleteClientDataIfPresent(clientId)) {
        logger.info("🗑️ Removing ${cause.label} client »$clientId«")

        SecurityEventLogger.logClientDeleted(clientId = clientId, reason = cause.reason.value)
        owner?.let { user -> fireClientRemoved(session, realm, user.id, clientId, kclient?.name, cause.reason) }
        kclient != null && realmProvider.removeClient(realm, kclient.id)
      } else {
        logger.info("⚠️️ Client »$clientId« has already been removed concurrently")

        false
      }
    }.toSet()
  }

  /**
   * Identifies client registrations in the pending state that have exceeded the TTL limit.
   *
   * @param batchSize The maximum number of client IDs to find.
   * @return An [Either] wrapping the set of expired client IDs.
   */
  private fun findExpiredClientRegistrations(batchSize: Int) =
      Either.catch { expirationService.findExpiredClientRegistrations(clientRegistrationTTL, batchSize).toSet() }

  /**
   * Identifies active clients that have been idle/expired beyond the client TTL limit and adds them to [expiredClientIds].
   *
   * @param expiredClientIds The expired client IDs found so far.
   * @param batchSize The maximum number of client IDs the result may hold.
   * @return An [Either] wrapping [expiredClientIds] plus the expired clients found.
   */
  private fun findExpiredClients(expiredClientIds: Set<String>, batchSize: Int) =
      Either.catch {
        val remaining = batchSize - expiredClientIds.size
        if (remaining > 0) expiredClientIds + expirationService.findExpiredClients(clientTTL, remaining) else expiredClientIds
      }

  /**
   * Identifies users that have been idle/expired beyond the user TTL limit.
   *
   * @param batchSize The maximum number of user names to find.
   * @return An [Either] wrapping the list of expired user names.
   */
  private fun findExpiredUsers(batchSize: Int) = Either.catch { expirationService.findExpiredUsers(userTTL, batchSize) }
}
