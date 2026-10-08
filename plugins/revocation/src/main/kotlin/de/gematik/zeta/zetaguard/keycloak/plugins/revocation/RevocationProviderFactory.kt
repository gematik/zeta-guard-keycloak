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
@file:Suppress("unused")

package de.gematik.zeta.zetaguard.keycloak.plugins.revocation

import de.gematik.zeta.zetaguard.keycloak.commons.server.REVOCATION_PROVIDER_ID
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import org.keycloak.Config
import org.keycloak.infinispan.util.InfinispanUtils
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.services.resource.RealmResourceProviderFactory

/** REST endpoint under .../realms/{realm}/zeta-guard-revocation */
open class RevocationProviderFactory : RealmResourceProviderFactory {
  /** Drives the keep-alive comments of every open subscription on this node. */
  private lateinit var scheduler: ScheduledExecutorService

  override fun getId() = REVOCATION_PROVIDER_ID

  override fun create(session: KeycloakSession) = RevocationProvider(session, scheduler)

  /**
   * In embedded mode the cache is ours to declare; in dedicated-Infinispan mode it lives on the server, outside this artifact and therefore able to
   * drift. Either way, resolving it here turns a broken setup into a boot failure instead of a revocation endpoint that answers 500s, or worse,
   * silently accepts reports nobody receives.
   */
  override fun postInit(factory: KeycloakSessionFactory) {
    KeycloakModelUtils.runJobInTransaction(factory) { session ->
      try {
        if (!InfinispanUtils.isRemoteInfinispan()) defineEmbeddedCache(session)
        BlockStore.of(session).probe()
      } catch (e: Exception) {
        throw IllegalStateException("cache '$REVOCATION_CACHE' is not available; $REVOCATION_PROVIDER_ID cannot operate without it", e)
      }
    }
  }

  override fun init(config: Config.Scope) {
    scheduler =
        Executors.newSingleThreadScheduledExecutor { runnable -> Thread(runnable, "zeta-guard-revocation-keepalive").apply { isDaemon = true } }
  }

  override fun close() {
    if (::scheduler.isInitialized) scheduler.shutdownNow()
  }
}
