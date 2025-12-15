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

package de.gematik.zeta.zetaguard.keycloak.commons

import de.gematik.zeta.zetaguard.keycloak.commons.server.INITIAL_ACCESS_TOKEN_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_CLIENT_REGISTRATION_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.KEYCLOAK_REALM_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.OIDC_CLIENT_REGISTRATION_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.USERINFO_PATH
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import jakarta.ws.rs.core.UriBuilder
import java.net.URI
import org.keycloak.constants.ServiceUrlConstants
import org.keycloak.models.KeycloakUriInfo

class KeycloakUriBuilder(private val uriBuilder: UriBuilder) {
  constructor(uriInfo: KeycloakUriInfo) : this(uriInfo.baseUriBuilder)

  constructor(
      hostname: String,
      port: Int,
      scheme: String,
      path: String,
  ) : this(UriBuilder.newInstance().host(hostname).port(mapPort(port, scheme)).scheme(scheme).path(path))

  fun tokenUrl(realm: String = ZETA_REALM) = createUri(ServiceUrlConstants.TOKEN_PATH, realm)

  fun authUrl(realm: String = ZETA_REALM) = createUri(ServiceUrlConstants.AUTH_PATH, realm)

  fun userinfoUrl(realm: String = ZETA_REALM) = createUri(USERINFO_PATH, realm)

  fun initialAccessTokenUrl(realm: String = ZETA_REALM) = createUri(INITIAL_ACCESS_TOKEN_PATH, realm)

  fun realmUrl(realm: String = ZETA_REALM) = createUri(KEYCLOAK_REALM_PATH, realm)

  fun clientRegistrationKeycloakUrl(realm: String = ZETA_REALM) = createUri(KEYCLOAK_CLIENT_REGISTRATION_PATH, realm)

  fun clientRegistrationOIDCUrl(realm: String = ZETA_REALM) = createUri(OIDC_CLIENT_REGISTRATION_PATH, realm)

  fun logoutUrl(realm: String = ZETA_REALM) = createUri(ServiceUrlConstants.TOKEN_SERVICE_LOGOUT_PATH, realm)

  fun createUri(path: String, realm: String): URI = uriBuilder.path(path.replace("\\{realm-name}".toRegex(), realm)).build()

  fun build(): URI = uriBuilder.build()
}

/**
 * Omit mentioning port, if defaults apply
 *
 * "audiences" may not match anymore, otherwise
 */
private fun mapPort(port: Int, scheme: String): Int =
    when (port) {
      443 if scheme == "https" -> -1
      80 if scheme == "http" -> -1
      else -> port
    }
