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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REALM_CLIENT_JOB_DISABLED
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_IDLE_CLIENT_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_IDLE_USER_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.SecurityEventLogger
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
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
private val CLIENT_REGISTRATION_TTL = System.getenv(ENV_CLIENT_REGISTRATION_TTL) ?: "PT5M"

/**
 * Configurable "Time-to-live" (TTL) of active clients before they are considered idle/expired.
 *
 * It is specified in ISO-8601 format and defaults to "P1Y" (1 year).
 */
private val IDLE_CLIENT_TTL = System.getenv(ENV_IDLE_CLIENT_TTL) ?: "P1Y"

/**
 * Configurable "Time-to-live" (TTL) of users before they are considered idle/expired.
 *
 * It is specified in ISO-8601 format and defaults to "P1Y" (1 year).
 */
private val IDLE_USER_TTL = System.getenv(ENV_IDLE_USER_TTL) ?: "P1Y"

private val clientTTL = IDLE_CLIENT_TTL.toDateTimePeriod()

private val userTTL = IDLE_USER_TTL.toDateTimePeriod()

private val clientRegistrationTTL = CLIENT_REGISTRATION_TTL.toDateTimePeriod()

/** Why a client registration is removed, used as log label. */
private enum class RemovalCause(val label: String) {
  /** Idle beyond the configured TTL (A_28808). */
  EXPIRED("expired"),
  /** Maximum number of clients per user exceeded (A_25748-02). */
  EVICTED("evicted"),
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

    deleteAndRemoveAllExpiredClients(session, realm, setOf(clientId), cause = RemovalCause.EVICTED).getOrElse {
      logger.error("⚠️ Failed to remove oldest client »$clientId« for user »$userName«", it)
      return false
    }

    SecurityEventLogger.logClientDeleted(clientId = clientId, reason = "max_clients_exceeded")

    return true
  }

  /**
   * Executes the expiration check and deletion logic for both clients and users.
   *
   * The job is skipped if the target realm [ZETA_REALM] is not found, or if it is temporarily disabled via the realm attribute
   * [ATTRIBUTE_REALM_CLIENT_JOB_DISABLED].
   *
   * @return The number of expired clients and users successfully removed.
   */
  fun runExpiration(): Pair<Int, Int> {
    logger.info("⏳ Checking for idle client registrations (TTL: $clientRegistrationTTL), clients (TTL: $clientTTL) and users (TTL: $userTTL)")

    val realm = session.realms().getRealmByName(ZETA_REALM)

    if (realm != null) {
      // Ability to disable cleanup job temporarily via realm attribute
      val jobDisabled = "true" == realm.attributes[ATTRIBUTE_REALM_CLIENT_JOB_DISABLED]

      if (jobDisabled) {
        logger.info("⏳ Client expiration job is disabled for realm »$ZETA_REALM«, skipping checks")
      } else {
        val expiredClientsIds =
            findAndAddAllExpiredClientRegistrations(mutableSetOf())
                .onRight { it.forEach { SecurityEventLogger.logClientRegistrationFail(clientId = it, "registration_expired") } }
                .flatMap { findAndAddAllExpiredClients(it) }
                .flatMap { deleteAndRemoveAllExpiredClients(session, realm, it) }
                .getOrElse {
                  logger.error("⚠️ Failed to expire clients", it)
                  throw it
                }

        val expiredUserIds =
            findExpiredUsers()
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
          val userModel = userProvider.getUserByUsername(realm, it)

          userProvider.removeUser(realm, userModel)
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
   * @return An [Either] containing a [Throwable] if the removal failed, or the set of deleted client IDs on success.
   */
  private fun deleteAndRemoveAllExpiredClients(
      session: KeycloakSession,
      realm: RealmModel,
      expiredClientIds: Set<String>,
      cause: RemovalCause = RemovalCause.EXPIRED,
  ) =
      Either.catch {
        val realmProvider = session.realmProvider

        expiredClientIds.forEach {
          logger.info("🗑️ Removing ${cause.label} client with id »$it«")

          realmProvider.removeClient(realm, it)
          dataService.deleteClientData(it)
        }

        expiredClientIds
      }

  /**
   * Identifies client registrations in the pending state that have exceeded the TTL limit and adds them to [expiredClientIds].
   *
   * @param expiredClientIds The mutable set to append expired client IDs to.
   * @return An [Either] wrapping the mutable set of expired client IDs.
   */
  private fun findAndAddAllExpiredClientRegistrations(expiredClientIds: MutableSet<String>) =
      Either.catch { expiredClientIds.also { it.addAll(expirationService.findExpiredClientRegistrations(clientRegistrationTTL)) } }

  /**
   * Identifies active clients that have been idle/expired beyond the client TTL limit and adds them to [expiredClientIds].
   *
   * @param expiredClientIds The mutable set to append expired client IDs to.
   * @return An [Either] wrapping the mutable set of expired client IDs.
   */
  private fun findAndAddAllExpiredClients(expiredClientIds: MutableSet<String>) =
      Either.catch { expiredClientIds.also { it.addAll(expirationService.findExpiredClients(clientTTL)) } }

  /**
   * Identifies users that have been idle/expired beyond the user TTL limit.
   *
   * @return An [Either] wrapping the list of expired user names.
   */
  private fun findExpiredUsers() = Either.catch { expirationService.findExpiredUsers(userTTL) }
}
