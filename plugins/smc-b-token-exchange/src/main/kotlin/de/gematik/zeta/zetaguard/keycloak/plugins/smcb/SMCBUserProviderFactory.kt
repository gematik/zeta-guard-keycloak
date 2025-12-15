/*-
 * #%L
 * referencevalidator-cli
 * %%
 * (C) akquinet tech@Spree GmbH, 2025, licensed for gematik GmbH, 2025, licensed for gematik GmbH
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
package de.gematik.zeta.zetaguard.keycloak.plugins.smcb

import de.gematik.zeta.zetaguard.keycloak.commons.server.SMCB_USER_PROVIDER_ID
import org.keycloak.connections.jpa.JpaConnectionProvider
import org.keycloak.models.UserProviderFactory

/**
 * User provider takes care that for newly created users the username is also used as the technical ID.
 *
 * Keycloak uses the technical for some reason to set the subject of the created token.
 *
 * See [org.keycloak.protocol.oidc.mappers.SubMapper.setClaim]
 */
class SMCBUserProviderFactory : UserProviderFactory<SMCBUserProvider> {
  override fun create(session: org.keycloak.models.KeycloakSession): SMCBUserProvider {
    val em = session.getProvider(JpaConnectionProvider::class.java).entityManager

    return SMCBUserProvider(session, em)
  }

  override fun init(config: org.keycloak.Config.Scope) {}

  override fun postInit(factory: org.keycloak.models.KeycloakSessionFactory) {}

  override fun close() {}

  override fun getId() = SMCB_USER_PROVIDER_ID

  override fun order() = 10 // Higher priority than JpaUserProviderFactory
}
