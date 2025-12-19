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

package de.gematik.zeta.zetaguard.keycloak.plugins.nonce

import de.gematik.zeta.zetaguard.keycloak.commons.server.ENV_NONCE_TTL
import de.gematik.zeta.zetaguard.keycloak.commons.server.NONCE_PROVIDER_ID
import java.time.Duration
import java.time.LocalDateTime
import org.keycloak.Config
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.services.resource.RealmResourceProviderFactory

// "Time-to-live" of a "nonce" in ISO-8601 format.
private val NONCE_TTL = System.getenv(ENV_NONCE_TTL) ?: "PT1H"

typealias TimeProvider = () -> LocalDateTime

/**
 * Nonce provider factory, see
 *
 * https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/gemSpec_ZETA_V1.1.0/#5.5.2.5.1
 */
open class NonceProviderFactory : RealmResourceProviderFactory {
  lateinit var nonceFactory: NonceFactory

  override fun getId() = NONCE_PROVIDER_ID

  override fun create(session: KeycloakSession) = NonceProvider(session, nonceFactory)

  override fun init(config: Config.Scope) {}

  override fun postInit(factory: KeycloakSessionFactory) {
    assert(!this::nonceFactory.isInitialized) { "NonceFactory already initialized" }

    nonceFactory = NonceFactory(timeProvider(), nonceTimeToLive())
  }

  // May be overriden for testing purposes
  protected open fun timeProvider(): TimeProvider = LocalDateTime::now

  // May be overriden for testing purposes
  protected open fun nonceTimeToLive(): Duration = Duration.parse(NONCE_TTL)

  override fun close() {}
}
