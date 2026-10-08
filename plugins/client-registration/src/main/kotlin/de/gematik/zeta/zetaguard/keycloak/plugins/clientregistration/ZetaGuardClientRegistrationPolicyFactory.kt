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

import de.gematik.zeta.zetaguard.keycloak.commons.server.CLIENT_REGISTRATION_POLICY_PROVIDER_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL
import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_CLIENT_REGISTRATION_STARTUP_DELAY
import de.gematik.zeta.zetaguard.keycloak.commons.server.IntegrityProviderService
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDateTimePeriod
import de.gematik.zeta.zetaguard.keycloak.commons.server.toDuration
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import io.quarkus.arc.Arc
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

private val CLIENT_REGISTRATION_INTERVAL = System.getenv(ENV_CLIENT_REGISTRATION_SCHEDULER_INTERVAL) ?: "PT5M"
private val clientExpirationJobInterval = CLIENT_REGISTRATION_INTERVAL.toDateTimePeriod()
private val CLIENT_REGISTRATION_STARTUP_DELAY = System.getenv(ENV_CLIENT_REGISTRATION_STARTUP_DELAY) ?: "PT20S"

/**
 * Setup initial state of newly created clients to "pending".
 *
 * Expired, i.e., unused client registrations will be deleted after a configurable amount of time.
 *
 * For details, see https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28808
 *
 * Realm configuration in 10-configure-client-registration-policies.sh
 */
class ZetaGuardClientRegistrationPolicyFactory : ClientRegistrationPolicyFactory {
  internal lateinit var integrityProviderService: IntegrityProviderService

  override fun create(session: KeycloakSession, model: ComponentModel) =
      ZetaGuardClientRegistrationPolicy(ZetaGuardDataService(DefaultEMCreator(session)), integrityProviderService)

  override fun getId(): String = CLIENT_REGISTRATION_POLICY_PROVIDER_ID

  override fun postInit(factory: KeycloakSessionFactory) {
    val timerProviderFactory = factory.getProviderFactory(TimerProvider::class.java) as TimerProviderFactory
    val delayUntil = LocalDateTime.now().plus(Duration.parse(CLIENT_REGISTRATION_STARTUP_DELAY))

    integrityProviderService = Arc.container().instance(IntegrityProviderService::class.java).get()

    logger.info("⏳ Checking for expired clients and users every $clientExpirationJobInterval")

    timerProviderFactory
        .create(factory.create())
        .schedule(
            {
              if (LocalDateTime.now().isAfter(delayUntil)) {
                runJobInTransaction(factory) {
                  val (expiredClients, expiredUsers) = ZetaGuardExpirationService(it).runExpiration()

                  if (expiredClients > 0 || expiredUsers > 0) {
                    logger.info("🗑️ Expired $expiredClients outdated clients and $expiredUsers outdated users")
                  }
                }
              }
            },
            clientExpirationJobInterval.toDuration().toMillis(),
            CLIENT_REGISTRATION_POLICY_PROVIDER_ID,
        )
  }

  override fun getHelpText(): String = "Setup newly created clients"

  override fun getConfigProperties() = listOf<ProviderConfigProperty>()

  override fun getConfigProperties(session: KeycloakSession) = getConfigProperties()

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun close() {
    // No-op
  }

  companion object {
    internal val logger: Logger = Logger.getLogger(ZetaGuardClientRegistrationPolicyFactory::class.java)
  }
}
