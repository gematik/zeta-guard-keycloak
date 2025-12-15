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
package de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration

import arrow.core.Either
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTESTATION_STATE_PENDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_ATTESTATION_STATE
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CREATED_AT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLIENT_REGISTRATION_POLICY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.SimpleSuccess
import de.gematik.zeta.zetaguard.keycloak.commons.server.Success
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDuration
import de.gematik.zeta.zetaguard.keycloak.commons.server.toLocalDateTime
import java.time.Duration
import java.time.LocalDateTime
import org.jboss.logging.Logger
import org.keycloak.Config
import org.keycloak.component.ComponentModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils.runJobInTransaction
import org.keycloak.provider.ProviderConfigProperty
import org.keycloak.services.clientregistration.policy.ClientRegistrationPolicyFactory
import org.keycloak.timer.TimerProvider
import org.keycloak.timer.TimerProviderFactory

// "Time-to-live" of a client registration in pending state in ISO-8601 format.
private val CLIENT_REGISTRATION_TTL = System.getenv(ENV_CLIENT_REGISTRATION_TTL) ?: "PT5M"
private val CLIENT_REGISTRATION_INTERVAL = System.getenv(ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL) ?: "PT2M"

/**
 * Setup initial state of newly created clients to "pending".
 *
 * Expired, i.e., unused client registrations will be deleted after a configurable amount of time.
 *
 * For details, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#5.5.2.4
 */
class ZetaGuardClientRegistrationPolicyFactory : ClientRegistrationPolicyFactory {
  override fun create(session: KeycloakSession, model: ComponentModel) = ZetaGuardClientRegistrationPolicy()

  override fun getId(): String = CLIENT_REGISTRATION_POLICY_PROVIDER_ID

  override fun postInit(factory: KeycloakSessionFactory) {
    val interval = Duration.parse(CLIENT_REGISTRATION_INTERVAL)
    val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory

    logger.debug("Checking for outdated client registrations every $interval")

    timerProviderFactory
        .create(factory.create())
        .schedule(
            {
              runJobInTransaction(factory) { //
                runExpiration(it).onLeft { //
                e ->
                  logger.warn("Error while checking for client registration expiration", e)
                }
              }
            },
            interval.toMillis(),
            CLIENT_REGISTRATION_POLICY_PROVIDER_ID,
        )
  }

  override fun getHelpText(): String = "Setup newly created clients"

  override fun getConfigProperties() = listOf<ProviderConfigProperty>()

  override fun getConfigProperties(session: KeycloakSession) = getConfigProperties()

  override fun init(config: Config.Scope) {}

  override fun close() {}

  private fun runExpiration(session: KeycloakSession): Either<Throwable, Success> =
      Either.catch {
        logger.info("Checking for outdated client registrations")
        val realm = session.realms().getRealmByName(ZETA_REALM)

        if (realm != null) { // May happen at startup
          val clients = session.clients()
          val timeToLive = CLIENT_REGISTRATION_TTL.toDuration()
          val outdatedClients =
              clients
                  .getClientsStream(realm) // Optimized/paginated stream
                  .filter { it.getAttribute(ATTRIBUTE_ATTESTATION_STATE) == ATTESTATION_STATE_PENDING }
                  .filter {
                    val createdAtString =
                        it.getAttribute(ATTRIBUTE_CREATED_AT)
                            ?: throw IllegalStateException("Missing client attribute $ATTRIBUTE_CREATED_AT for client ${it.clientId}")
                    val createdAt = createdAtString.toLocalDateTime()
                    val expiresAt = createdAt.plus(timeToLive)

                    LocalDateTime.now().isAfter(expiresAt)
                  }
                  .map { it.id }
                  .toList()

          logger.info("Outdated client registrations: $outdatedClients")

          outdatedClients.forEach { clients.removeClient(realm, it) }
        }

        SimpleSuccess
      }

  companion object {
    private val logger: Logger = Logger.getLogger(ZetaGuardClientRegistrationPolicyFactory::class.java)
  }
}
