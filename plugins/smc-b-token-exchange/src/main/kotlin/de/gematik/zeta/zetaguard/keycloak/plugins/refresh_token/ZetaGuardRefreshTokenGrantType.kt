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
import de.gematik.zeta.zetaguard.keycloak.commons.opa.opaTtlDurations
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REQUESTED_SCOPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.OPA_HTTP_CLIENT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ZETA_REALM
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.isSuccessStatus
import de.gematik.zeta.zetaguard.keycloak.commons.server.logger
import de.gematik.zeta.zetaguard.keycloak.commons.server.lookupHttpClient
import de.gematik.zeta.zetaguard.keycloak.commons.server.permitMobileIssuance
import de.gematik.zeta.zetaguard.keycloak.commons.server.rememberLastClientIp
import de.gematik.zeta.zetaguard.keycloak.jpa.DefaultEMCreator
import de.gematik.zeta.zetaguard.keycloak.plugins.ZetaGuardTokenManager
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.ZetaGuardDataService
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import jakarta.ws.rs.core.Response
import jakarta.ws.rs.core.Response.Status.BAD_REQUEST
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException
import org.keycloak.OAuthErrorException.INVALID_REQUEST
import org.keycloak.events.Details
import org.keycloak.events.Errors
import org.keycloak.models.UserSessionModel
import org.keycloak.protocol.oidc.grants.OAuth2GrantType
import org.keycloak.protocol.oidc.grants.RefreshTokenGrantType
import org.keycloak.representations.RefreshToken
import org.keycloak.services.CorsErrorResponseException

class ZetaGuardRefreshTokenGrantType(private val opaConfig: OPAConfig = OPAConfig()) : RefreshTokenGrantType() {
  override fun setContext(context: OAuth2GrantType.Context) {
    super.setContext(context)
    // Override value, in order to implement org.keycloak.protocol.oidc.mappers.OIDCRefreshTokenMapper feature
    // and to use ZetaGuardRefreshToken
    tokenManager = ZetaGuardTokenManager()
  }

  override fun process(context: OAuth2GrantType.Context): Response {
    if (context.client.realm.name != ZETA_REALM) { // Short-circuit for clients like admin-cli@master realm
      return super.process(context)
    }

    setContext(context)

    val encodedRefreshToken = formParams.getFirst(OAuth2Constants.REFRESH_TOKEN) ?: throw CorsErrorResponseException(
        cors, INVALID_REQUEST, "No refresh token", BAD_REQUEST
    )

    session.setAttribute(ATTRIBUTE_REQUESTED_SCOPES, getRequestedScopes())

    val refreshToken = try {
      tokenManager.verifyRefreshToken(session, realm, client, request, encodedRefreshToken, true)
    } catch (e: OAuthErrorException) {
      event.detail(Details.REASON, e.getDescription())
      event.error(Errors.INVALID_TOKEN)
      throw CorsErrorResponseException(cors, e.getError(), e.getDescription(), BAD_REQUEST)
    } catch (e: Throwable) {
      logger.error("Error while processing refresh token", e)
      throw CorsErrorResponseException(cors, INVALID_REQUEST, "Error while processing refresh token", BAD_REQUEST)
    }

    // Skip OPA for non-SMC-B/mobile clients sessions (e.g. master/admin-cli).
    val userSession = refreshToken.sessionId?.let { session.sessions().getUserSession(realm, it) } ?: return super.process(context)
    val replay = refreshOpaReplay(userSession)
    if (lacksMobileGateDecision(userSession, replay, client.id)) {
      throw noMobileGateDecision()
    }
    if (replay == null) {
      return super.process(context)
    }
    val httpClient = session.lookupHttpClient(OPA_HTTP_CLIENT_ID)

    return when (val outcome = OpaGateEnforcer.enforce(httpClient, refreshInput(refreshToken, replay), opaConfig)) {
      is OpaGateEnforcer.Outcome.Skip -> {
        logger.warn("OPA enforcer returned Skip for refresh_token grant — gate not configured for this grant type")
        if (replay is RefreshOpaReplay.Mobile) {
          throw noMobileGateDecision()
        }
        super.process(context)
      }

      is OpaGateEnforcer.Outcome.Allow -> {
        applyOpaTtls(userSession, replay, outcome.accessTokenTtl, outcome.refreshTokenTtl)
        if (replay is RefreshOpaReplay.Mobile) {
          session.permitMobileIssuance(client)
        }
        val response = super.process(context)

        if (response.isSuccessStatus()) {
          outcome.payload?.let(::storeSessionData)
        }

        if (replay is RefreshOpaReplay.Mobile && response.isSuccessStatus()) {
          rememberLastClientIp(session, client)
        }

        response
      }

      is OpaGateEnforcer.Outcome.Deny -> throw mapToCorsException(outcome.error, cors, event)
      is OpaGateEnforcer.Outcome.Error -> throw mapToCorsException(outcome.error, cors, event)
    }
  }

  // A KVNR token can't be issued without a gate decision of this client: answer invalid_grant, so the client signs in again
  private fun noMobileGateDecision(): CorsErrorResponseException {
    val description = "No mobile gate decision for this client, sign in again"
    event.detail(Details.REASON, description)
    event.error(Errors.INVALID_TOKEN)
    return CorsErrorResponseException(cors, OAuthErrorException.INVALID_GRANT, description, BAD_REQUEST)
  }

  // A_26586-01: store the policy engine input as session data of the client
  private fun storeSessionData(opaInput: String) {
    val clientData = ZetaGuardDataService(DefaultEMCreator(session)).findClientData(client.clientId)

    if (clientData == null) {
      logger.warnf("No client data found for »%s«, session data not stored", client.clientId)
    } else {
      clientData.storeSessionData(opaInput)
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

    return buildRefreshOpaInput(session, refreshToken, replay, ipAddress, previousIp)
  }
}
