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
package de.gematik.zeta.zetaguard.keycloak.plugins.refresh_token

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import jakarta.ws.rs.core.Response
import java.time.Duration
import org.keycloak.OAuth2Constants
import org.keycloak.connections.httpclient.HttpClientProvider
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.grants.OAuth2GrantType
import org.keycloak.protocol.oidc.grants.RefreshTokenGrantType
import org.keycloak.representations.RefreshToken

class ZetaGuardRefreshTokenGrantType(private val opaConfig: OPAConfig = OPAConfig()) : RefreshTokenGrantType() {
  override fun setContext(context: OAuth2GrantType.Context) {
    super.setContext(context)
    // Override value, in order to implement org.keycloak.protocol.oidc.mappers.OIDCRefreshTokenMapper feature
    // and to use ZetaGuardRefreshToken
    tokenManager = ZetaGuardTokenManager()
  }

  override fun process(context: OAuth2GrantType.Context): Response {
    setContext(context)

    val encodedRefreshToken = formParams.getFirst(OAuth2Constants.REFRESH_TOKEN) ?: return super.process(context)

    // Pre-validate so OPA sees verified claims; defer to super on any failure so it emits the canonical CORS error.
    val refreshToken =
        try {
          tokenManager.verifyRefreshToken(session, realm, client, request, encodedRefreshToken, true)
        } catch (e: Throwable) {
          logger.debugf(e, "refresh-token pre-validation failed, deferring to upstream grant")
          return super.process(context)
        }

    // Skip OPA for non-SMC-B sessions (e.g. master/admin-cli).
    val userSession = refreshToken.sessionId?.let { session.sessions().getUserSession(realm, it) }
    val note = userSession?.getNote(ATTRIBUTE_SMCB_CONTEXT) ?: return super.process(context)
    val data = note.toObject<ZetaGuardTokenExchangeData>()

    val httpClient = session.getProvider(HttpClientProvider::class.java)?.httpClient

    return when (val outcome = OpaGateEnforcer.enforce(httpClient, buildOpaInput(refreshToken, data), opaConfig, logger)) {
      is OpaGateEnforcer.Outcome.Skip -> {
        logger.warn("OPA enforcer returned Skip for refresh_token grant — gate not configured for this grant type")
        super.process(context)
      }

      is OpaGateEnforcer.Outcome.Allow -> {
        applyOpaTtls(userSession, data, outcome.accessTokenTtl, outcome.refreshTokenTtl)
        super.process(context)
      }

      is OpaGateEnforcer.Outcome.Deny -> throw mapToCorsException(outcome.error, cors, event)
      is OpaGateEnforcer.Outcome.Error -> throw mapToCorsException(outcome.error, cors, event)
    }
  }

  // Stamp OPA TTLs onto the session note so ZetaGuardAccessTokenMapper picks them up.
  private fun applyOpaTtls(userSession: UserSessionModel, data: ZetaGuardTokenExchangeData, accessTtl: Int?, refreshTtl: Int?) {
    if (accessTtl == null || refreshTtl == null) {
      logger.warnf("OPA returned partial TTLs (access=%s, refresh=%s) — skip note update!", accessTtl, refreshTtl)
      return
    }
    val updated = data.copy(accessTokenTTL = Duration.ofSeconds(accessTtl.toLong()), refreshTokenTTL = Duration.ofSeconds(refreshTtl.toLong()))
    userSession.setNote(ATTRIBUTE_SMCB_CONTEXT, updated.toJSON())
  }

  private fun buildOpaInput(refreshToken: RefreshToken, data: ZetaGuardTokenExchangeData): OpaGateInput {
    // Replay exchange-time audiences/scopes from the session note; fall back to the token's scope on legacy notes.
    val scopes = data.scopes ?: refreshToken.scope?.split(' ')?.filter { it.isNotBlank() } ?: emptyList()
    val audiences = data.audiences

    return OpaGateInput(
        grantType = OAuth2Constants.REFRESH_TOKEN,
        scopes = scopes,
        audiences = audiences,
        ipAddress = session.context.connection?.remoteAddr,
        userProfessionOid = refreshToken.otherClaims[CLAIM_PROFESSION_OID] as? String,
        clientProductID = refreshToken.otherClaims[CLAIM_PRODUCT_ID] as? String,
        clientProductVersion = refreshToken.otherClaims[CLAIM_PRODUCT_VERSION] as? String,
        authenticationMethodsReferences = data.authenticationMethodsReferences,
        clientId = data.clientId,
        clientPlatform = data.clientPlatform,
        clientRegistrationTimestamp = data.clientRegistrationTimestamp,
        postureType = data.postureType,
        previousIpAddress = data.previousIpAddress,
        userIdentifier = data.telematikID,
    )
  }
}
