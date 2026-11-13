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
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REQUESTED_SCOPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SESSION_END
import de.gematik.zeta.zetaguard.keycloak.commons.server.toScope
import de.gematik.zeta.zetaguard.keycloak.commons.server.toScopes
import org.keycloak.TokenCategory
import org.keycloak.events.EventBuilder
import org.keycloak.http.HttpRequest
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
      clientSessionCtx: ClientSessionContext,
  ): AccessTokenResponseBuilder = ZetaGuardAccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx)

  /**
   * A_29843: Allow requesting scopes in a refresh token grant that were not originally granted.
   *
   * [TokenManager.refreshAccessToken] intersects the requested scopes with the scope of the refresh token (RFC 6749, section 6), thus
   * dropping all new scopes. Widening the scope of the verified refresh token makes the new access token contain exactly the requested
   * scopes, while all other checks (session, consent, token reuse, protocol mappers) are still performed by Keycloak.
   */
  override fun verifyRefreshToken(
      session: KeycloakSession,
      realm: RealmModel,
      client: ClientModel,
      request: HttpRequest,
      encodedRefreshToken: String,
      checkExpiration: Boolean,
  ): RefreshToken {
    val refreshToken = super.verifyRefreshToken(session, realm, client, request, encodedRefreshToken, checkExpiration)
    // Set by ZetaGuardRefreshTokenGrantType to pass validated request scopes, otherwise (logout request, e.g.) proceed as usual
    @Suppress("UNCHECKED_CAST")
    val rawRequestedScopes = session.getAttribute(ATTRIBUTE_REQUESTED_SCOPES) as? String ?: return refreshToken
    val requestedScopes = rawRequestedScopes.toScopes()
    val originalScopes = refreshToken.scope.toScopes()
    val newScopes = requestedScopes - originalScopes

    refreshToken.scope = (originalScopes + newScopes).toScope()

    return refreshToken
  }

  inner class ZetaGuardAccessTokenResponseBuilder(
      realm: RealmModel,
      client: ClientModel,
      event: EventBuilder,
      private val session: KeycloakSession,
      private val userSession: UserSessionModel,
      private val clientSessionCtx: ClientSessionContext,
  ) : AccessTokenResponseBuilder(realm, client, event, session, userSession, clientSessionCtx) {

    override fun generateRefreshToken(): AccessTokenResponseBuilder {
      super.generateRefreshToken()
      val realmSessionEnd = refreshToken.exp

      refreshToken(createZetaGuardRefreshToken(refreshToken))
      transformRefreshToken()
      capExpiration(realmSessionEnd)

      // First refresh token after full authentication: its exp ends the session (A_25662)
      refreshToken.exp?.let {
        if (userSession.getNote(ATTRIBUTE_SESSION_END) == null) {
          userSession.setNote(ATTRIBUTE_SESSION_END, it.toString())
        }
      }

      return this
    }

    override fun generateRefreshToken(oldRefreshToken: RefreshToken, clientSession: AuthenticatedClientSessionModel): AccessTokenResponseBuilder {
      super.generateRefreshToken(oldRefreshToken, clientSession)

      val realmSessionEnd = refreshToken.exp
      refreshToken(createZetaGuardRefreshToken(refreshToken))
      transformRefreshToken()
      capExpiration(realmSessionEnd, userSession.getNote(ATTRIBUTE_SESSION_END)?.toLongOrNull())

      return this
    }

    /**
     * Keep the refresh token from outliving its session.
     *
     * The PDP TTL set by the mappers replaces the exp Keycloak derived from the realm's session idle/max limits. Without this
     * cap the token (and refresh_expires_in) promised more than the session delivers, and a refresh past the session end
     * failed with "Session not active". Rotation must not extend the session beyond the first refresh token's exp either
     * (A_25662).
     */
    private fun capExpiration(vararg sessionEnds: Long?) {
      listOfNotNull(refreshToken.exp, *sessionEnds).minOrNull()?.let { refreshToken.exp(it) }
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
