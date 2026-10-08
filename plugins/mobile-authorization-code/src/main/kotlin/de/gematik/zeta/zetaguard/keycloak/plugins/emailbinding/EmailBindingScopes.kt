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
package de.gematik.zeta.zetaguard.keycloak.plugins.emailbinding

import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_EMAIL_BINDING
import de.gematik.zeta.zetaguard.keycloak.commons.server.SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientScopeModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.utils.KeycloakModelUtils
import org.keycloak.services.util.DefaultClientSessionContext

internal val EMAIL_BINDING_SCOPE_NAMES = setOf(SCOPE_EMAIL_BINDING, SCOPE_COMPLETE_REGISTRATION_BY_EMAIL_VERIFICATION)

internal fun ClientSessionContext.withTokenScopesReducedTo(
    session: KeycloakSession,
    scopeNames: Set<String>,
): ClientSessionContext {
  val defaultScopeIds = clientSession.client.getClientScopes(true).values.mapTo(HashSet()) { it.id }
  val kept = LinkedHashMap<String, ClientScopeModel>()

  clientScopesStream
      .filter { it is ClientModel || (!it.isIncludeInTokenScope && it.id in defaultScopeIds) }
      .forEach { kept[it.id] = it }

  scopeNames.forEach { name ->
    val scope =
        KeycloakModelUtils.getClientScopeByName(clientSession.realm, name)
            ?: throw IllegalStateException("Client scope '$name' not found.")
    kept[scope.id] = scope
  }

  return DefaultClientSessionContext.fromClientSessionAndClientScopes(clientSession, kept.values.toSet(), null, session)
}
