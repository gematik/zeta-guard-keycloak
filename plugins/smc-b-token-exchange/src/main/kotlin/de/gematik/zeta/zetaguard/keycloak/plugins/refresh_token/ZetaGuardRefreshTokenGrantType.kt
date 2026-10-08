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
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.opa.opaTtlDurations
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.httpClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.isSuccessStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.rememberLastClientIp
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.logger
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import jakarta.ws.rs.core.Response
import org.keycloak.OAuth2Constants
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

    // Skip OPA for non-SMC-B/mobile clients sessions (e.g. master/admin-cli).
    val userSession = refreshToken.sessionId?.let { session.sessions().getUserSession(realm, it) } ?: return super.process(context)
    val replay = refreshOpaReplay(userSession) ?: return super.process(context)
    val httpClient = session.httpClient

    return when (val outcome = OpaGateEnforcer.enforce(httpClient, refreshInput(refreshToken, replay), opaConfig)) {
      is OpaGateEnforcer.Outcome.Skip -> {
        logger.warn("OPA enforcer returned Skip for refresh_token grant — gate not configured for this grant type")
        super.process(context)
      }

      is OpaGateEnforcer.Outcome.Allow -> {
        applyOpaTtls(userSession, replay, outcome.accessTokenTtl, outcome.refreshTokenTtl)
        val response = super.process(context)
        if (replay is RefreshOpaReplay.Mobile && response.isSuccessStatus()) {
          rememberLastClientIp(session, client)
        }
        response
      }

      is OpaGateEnforcer.Outcome.Deny -> throw mapToCorsException(outcome.error, cors, event)
      is OpaGateEnforcer.Outcome.Error -> throw mapToCorsException(outcome.error, cors, event)
    }
  }

  // Stamp OPA TTLs onto the session note so ZetaGuardAccessTokenMapper picks them up.
  private fun applyOpaTtls(userSession: UserSessionModel, replay: RefreshOpaReplay, accessTtl: Int?, refreshTtl: Int?) {
    val ttls = opaTtlDurations(accessTtl, refreshTtl) ?: return
    when (replay) {
      is RefreshOpaReplay.Smcb ->
        userSession.setNote(
            ATTRIBUTE_SMCB_CONTEXT,
            replay.data.copy(accessTokenTTL = ttls.first, refreshTokenTTL = ttls.second).toJSON(),
        )

      is RefreshOpaReplay.Mobile ->
        userSession.setNote(
            ATTRIBUTE_MOBILE_OPA_CONTEXT,
            replay.data.copy(accessTokenTTL = ttls.first, refreshTokenTTL = ttls.second).toJSON(),
        )
    }
  }

  private fun refreshInput(refreshToken: RefreshToken, replay: RefreshOpaReplay): OpaGateInput {
    val ipAddress =
        when (replay) {
          is RefreshOpaReplay.Smcb -> session.context.connection?.remoteAddr
          is RefreshOpaReplay.Mobile -> session.clientIP
        }
    val previousIp = client.attributes[ATTRIBUTE_LAST_CLIENT_IP]
    return buildRefreshOpaInput(refreshToken, replay, ipAddress, previousIp)
  }
}

internal sealed interface RefreshOpaReplay {
  data class Smcb(val data: ZetaGuardTokenExchangeData) : RefreshOpaReplay

  data class Mobile(val data: OpaSessionContext) : RefreshOpaReplay
}

internal fun refreshOpaReplay(userSession: UserSessionModel?): RefreshOpaReplay? {
  if (userSession == null) return null
  userSession.getNote(ATTRIBUTE_SMCB_CONTEXT)?.let {
    return RefreshOpaReplay.Smcb(it.toObject())
  }
  userSession.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT)?.let {
    return RefreshOpaReplay.Mobile(it.toObject())
  }
  return null
}

internal fun buildRefreshOpaInput(
    refreshToken: RefreshToken,
    replay: RefreshOpaReplay,
    ipAddress: String?,
    previousIpAddress: String?,
): OpaGateInput =
    when (replay) {
      is RefreshOpaReplay.Smcb -> {
        val data = replay.data
        val scopes = data.scopes ?: refreshToken.scope?.split(' ')?.filter { it.isNotBlank() } ?: emptyList()
        OpaGateInput(
            grantType = OAuth2Constants.REFRESH_TOKEN,
            scopes = scopes,
            audiences = data.audiences,
            ipAddress = ipAddress,
            userProfessionOid = refreshToken.otherClaims[CLAIM_PROFESSION_OID] as? String,
            clientProductID = refreshToken.otherClaims[CLAIM_PRODUCT_ID] as? String,
            clientProductVersion = refreshToken.otherClaims[CLAIM_PRODUCT_VERSION] as? String,
            authenticationMethodsReferences = data.authenticationMethodsReferences,
            authenticationContextClassReference = data.authenticationContextClassReference,
            clientId = data.clientId,
            clientPlatform = data.clientPlatform,
            clientRegistrationTimestamp = data.clientRegistrationTimestamp,
            postureType = data.postureType,
            previousIpAddress = data.previousIpAddress,
            userIdentifier = data.telematikID,
            deviceInfo = data.deviceInfo,
        )
      }

      is RefreshOpaReplay.Mobile -> {
        val data = replay.data
        val scopes =
            data.scopes?.filter { it.isNotBlank() }?.ifEmpty { null }
              ?: refreshToken.scope?.split(' ')?.filter { it.isNotBlank() }
              ?: emptyList()
        OpaGateInput(
            grantType = OAuth2Constants.REFRESH_TOKEN,
            scopes = scopes,
            audiences = data.audiences,
            ipAddress = ipAddress,
            userProfessionOid = data.userProfessionOid ?: refreshToken.otherClaims[CLAIM_PROFESSION_OID] as? String,
            clientProductID = data.clientProductID ?: refreshToken.otherClaims[CLAIM_PRODUCT_ID] as? String,
            clientProductVersion = data.clientProductVersion ?: refreshToken.otherClaims[CLAIM_PRODUCT_VERSION] as? String,
            authenticationMethodsReferences = data.authenticationMethodsReferences.orEmpty(),
            authenticationContextClassReference = data.authenticationContextClassReference,
            clientId = data.clientId,
            clientPlatform = data.clientPlatform,
            clientRegistrationTimestamp = data.clientRegistrationTimestamp,
            postureType = data.postureType,
            previousIpAddress = previousIpAddress ?: "Unknown",
            userIdentifier = data.userIdentifier,
            userCommonName = data.userCommonName,
            deviceInfo = data.deviceInfo,
        )
      }
    }

