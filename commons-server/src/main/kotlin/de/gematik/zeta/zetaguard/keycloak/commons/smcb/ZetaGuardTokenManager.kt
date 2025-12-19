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
package de.gematik.zeta.zetaguard.keycloak.commons.smcb

import org.keycloak.events.EventBuilder
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.ClientSessionContext
import org.keycloak.models.KeycloakSession
import org.keycloak.models.RealmModel
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.ProtocolMapperUtils
import org.keycloak.protocol.oidc.TokenManager
import org.keycloak.protocol.oidc.mappers.OIDCRefreshTokenMapper
import org.keycloak.representations.RefreshToken

/**
 * The default implementation of KC unfortunately does not have a concept of refresh token mappers. The default token mapper is created in
 * [org.keycloak.protocol.oidc.OIDCLoginProtocolService],
 *
 * Thus we have no means to influence the claims of a refresh token but by overriding the default code.
 */
class ZetaGuardTokenManager : TokenManager() {

  override fun responseBuilder(
      realm: RealmModel,
      client: ClientModel,
      event: EventBuilder,
      session: KeycloakSession,
      userSession: UserSessionModel,
      clientSessionCtx: ClientSessionContext,
  ) = ZetaGuardTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx)

  inner class ZetaGuardTokenResponseBuilder(
      realm: RealmModel,
      client: ClientModel,
      event: EventBuilder,
      val keycloakSession: KeycloakSession,
      val userSessionModel: UserSessionModel,
      val clientSessionContext: ClientSessionContext,
  ) : AccessTokenResponseBuilder(realm, client, event, keycloakSession, userSessionModel, clientSessionContext) {

    override fun generateRefreshToken(refreshToken: RefreshToken, clientSession: AuthenticatedClientSessionModel): ZetaGuardTokenResponseBuilder {
      super.generateRefreshToken(refreshToken, clientSession)

      transformRefreshToken()

      return this
    }

    override fun generateRefreshToken(): ZetaGuardTokenResponseBuilder {
      super.generateRefreshToken()

      transformRefreshToken()

      return this
    }

    private fun transformRefreshToken() {
      ProtocolMapperUtils.getSortedProtocolMappers(keycloakSession, clientSessionContext)
          .toList()
          .filter { it.value is OIDCRefreshTokenMapper }
          .forEach {
            val mapper = it.value as OIDCRefreshTokenMapper

            mapper.transformRefreshToken(refreshToken, it.key, keycloakSession, userSessionModel, clientSessionContext)
          }
    }
  }
}
