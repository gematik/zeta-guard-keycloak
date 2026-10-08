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

import de.gematik.zeta.zetaguard.keycloak.commons.server.REVOCATION_EVENTLISTENER_PROVIDER_ID
import org.keycloak.Config
import org.keycloak.events.EventListenerProviderFactory
import org.keycloak.models.KeycloakSession
import org.keycloak.models.KeycloakSessionFactory

/** Records a block whenever a session ends, however it ended. Must be listed in the realm's `eventsListeners` to take effect. */
open class RevocationEventListenerFactory : EventListenerProviderFactory {
  override fun getId() = REVOCATION_EVENTLISTENER_PROVIDER_ID

  override fun create(session: KeycloakSession) = RevocationEventListener(session)

  override fun postInit(factory: KeycloakSessionFactory) {
    // No-op
  }

  override fun init(config: Config.Scope) {
    // No-op
  }

  override fun close() {
    // No-op
  }
}
