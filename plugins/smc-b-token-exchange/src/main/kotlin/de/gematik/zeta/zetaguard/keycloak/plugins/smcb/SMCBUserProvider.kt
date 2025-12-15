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

import jakarta.persistence.EntityManager
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserModel
import org.keycloak.models.jpa.JpaUserProvider

/**
 * User provider takes care that for newly created (SMC-B) users the username is also used as the technical ID.
 *
 * Keycloak for some reason uses the technical ID to set the subject of the created token.
 *
 * The subject however is required to match the "Telematik-ID" of the user, stored in the user name, not the technical ID.
 *
 * See [org.keycloak.protocol.oidc.mappers.SubMapper.setClaim]
 */
class SMCBUserProvider(session: KeycloakSession, em: EntityManager) : JpaUserProvider(session, em) {
  override fun addUser(realm: RealmModel, username: String): UserModel {
    val user = username.lowercase()

    return addUser(realm, user, user, true, true)
  }
}
