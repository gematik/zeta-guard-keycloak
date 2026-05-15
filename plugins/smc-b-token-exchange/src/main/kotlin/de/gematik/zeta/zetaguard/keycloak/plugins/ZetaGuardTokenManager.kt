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
package de.gematik.zeta.zetaguard.keycloak.plugins

import com.fasterxml.jackson.annotation.JacksonInject
import com.fasterxml.jackson.annotation.JsonCreator
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObjectWithCreator
import org.keycloak.TokenCategory
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
 * Enhanced replacement for default [TokenManager] implementation, enabling [OIDCRefreshTokenMapper] support
 *
 * See also: https://gemspec.gematik.de/docs/gemSpec/gemSpec_ZETA/latest/#A_28527
 */
class ZetaGuardTokenManager : TokenManager() {
  override fun responseBuilder(
    realm: RealmModel,
    client: ClientModel,
    event: EventBuilder,
    session: KeycloakSession,
    userSession: UserSessionModel,
    clientSessionCtx: ClientSessionContext
  ): AccessTokenResponseBuilder = ZetaGuardAccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx)

  inner class ZetaGuardAccessTokenResponseBuilder(
    realm: RealmModel,
    client: ClientModel,
    event: EventBuilder,
    private val session: KeycloakSession,
    private val userSession: UserSessionModel,
    private val clientSessionCtx: ClientSessionContext
  ) : AccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx) {

    override fun generateRefreshToken(): AccessTokenResponseBuilder {
      super.generateRefreshToken()
      refreshToken(createZetaGuardRefreshToken(refreshToken))
      transformRefreshToken()
      return this
    }

    override fun generateRefreshToken(oldRefreshToken: RefreshToken, clientSession: AuthenticatedClientSessionModel): AccessTokenResponseBuilder {
      super.generateRefreshToken(oldRefreshToken, clientSession)
      refreshToken(createZetaGuardRefreshToken(refreshToken))
      transformRefreshToken()
      return this
    }

    /**
     * Create ZetaGuardRefreshToken from RefreshToken by serializing and deserializing the original token.
     *
     * This way all relevant fields are copied.
     */
    private fun createZetaGuardRefreshToken(refreshToken: RefreshToken) =
      refreshToken.toJSON().toObjectWithCreator<ZetaGuardRefreshToken>(mapOf(PARAM_REFRESH_TOKEN to refreshToken))

    /**
     * Apply transformations to refresh token.
     *
     * Analogous to use of [org.keycloak.protocol.oidc.mappers.OIDCAccessTokenMapper]
     */
    private fun transformRefreshToken() {
      ProtocolMapperUtils.getSortedProtocolMappers(session, clientSessionCtx)
        .filter { it.value is OIDCRefreshTokenMapper }
        .forEach {
          val mapper = it.value as OIDCRefreshTokenMapper

          mapper.transformRefreshToken(refreshToken, it.key, session, userSession, clientSessionCtx)
        }
    }
  }
}

private const val PARAM_REFRESH_TOKEN = "refresh_token"

class ZetaGuardRefreshToken @JsonCreator constructor(@JacksonInject(PARAM_REFRESH_TOKEN) token: RefreshToken) : RefreshToken(token) {
  /**
   * See https://ey-fp-dev.atlassian.net/browse/ZETAP-959
   *
   * Override default value INTERNAL, causing the refresh token to be signed with the hard-coded "HS512" algorithm. Effectively, this makes the
   * algorithm configurable via the client's ID token configuration parameter
   * [org.keycloak.protocol.oidc.OIDCConfigAttributes.ID_TOKEN_SIGNED_RESPONSE_ALG].
   */
  override fun getCategory(): TokenCategory = TokenCategory.ID
}
