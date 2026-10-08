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
package de.gematik.zeta.zetaguard.keycloak.plugins.mobile

import de.gematik.zeta.zetaguard.keycloak.client_assertion.ClientStatementData
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toJSON
import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.opa.opaTtlDurations
import de.gematik.zeta.zetaguard.keycloak.commons.opa.toOpaDeviceInfo
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_CLIENT_STATEMENT_RAW
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_LAST_CLIENT_IP
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_ACR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_AMR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.KeycloakError
import de.gematik.zeta.zetaguard.keycloak.commons.server.clientIP
import de.gematik.zeta.zetaguard.keycloak.commons.server.httpClient
import de.gematik.zeta.zetaguard.keycloak.plugins.clientregistration.model.ZetaGuardClientData
import de.gematik.zeta.zetaguard.keycloak.plugins.mapToCorsException
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OPAConfig
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateEnforcer
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import jakarta.ws.rs.core.MultivaluedMap
import jakarta.ws.rs.core.Response
import java.time.ZoneOffset
import org.jboss.logging.Logger
import org.keycloak.OAuth2Constants
import org.keycloak.OAuthErrorException.UNSUPPORTED_GRANT_TYPE
import org.keycloak.events.EventBuilder
import org.keycloak.models.AuthenticatedClientSessionModel
import org.keycloak.models.ClientModel
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserSessionModel
import org.keycloak.services.cors.Cors

private val logger: Logger = Logger.getLogger(MobileOpaGate::class.java)

class MobileOpaGate(private val opaConfig: OPAConfig) {
  data class Request(
      val session: KeycloakSession,
      val client: ClientModel,
      val userSession: UserSessionModel,
      val grantType: String,
      val scopes: List<String>,
      val audiences: List<String>?,
      val clientData: ZetaGuardClientData,
      val cors: Cors,
      val event: EventBuilder,
  )

  fun enforce(request: Request) {
    val input = buildInput(request)
    when (val outcome = OpaGateEnforcer.enforce(request.session.httpClient, input, opaConfig)) {
      is OpaGateEnforcer.Outcome.Skip ->
        throw mapToCorsException(
            KeycloakError(UNSUPPORTED_GRANT_TYPE, "Unsupported grant type", Response.Status.BAD_REQUEST),
            request.cors,
            request.event,
        )

      is OpaGateEnforcer.Outcome.Allow -> storeContext(request.userSession, input, outcome.accessTokenTtl, outcome.refreshTokenTtl)

      is OpaGateEnforcer.Outcome.Deny -> throw mapToCorsException(outcome.error, request.cors, request.event)
      is OpaGateEnforcer.Outcome.Error -> throw mapToCorsException(outcome.error, request.cors, request.event)
    }
  }

  /**
   * Persist the OPA Allow snapshot on the user session.
   *
   * Token issuance and refresh do not share in-memory state: `ZetaGuardAccessTokenMapper` later
   * reads the TTLs to set `exp`, and refresh rebuilds [OpaGateInput] from this note instead of
   * re-collecting client statement / KVNR / scopes from the original request.
   */
  private fun storeContext(userSession: UserSessionModel, input: OpaGateInput, accessTtl: Int?, refreshTtl: Int?) {
    val ttls = opaTtlDurations(accessTtl, refreshTtl) ?: return
    userSession.setNote(
        ATTRIBUTE_MOBILE_OPA_CONTEXT,
        OpaSessionContext(
                accessTokenTTL = ttls.first,
                refreshTokenTTL = ttls.second,
                scopes = input.scopes,
                audiences = input.audiences,
                clientId = input.clientId,
                clientPlatform = input.clientPlatform,
                clientRegistrationTimestamp = input.clientRegistrationTimestamp,
                postureType = input.postureType,
                clientProductID = input.clientProductID,
                clientProductVersion = input.clientProductVersion,
                authenticationMethodsReferences = input.authenticationMethodsReferences,
                authenticationContextClassReference = input.authenticationContextClassReference,
                userIdentifier = input.userIdentifier,
                userProfessionOid = input.userProfessionOid,
                userCommonName = input.userCommonName,
                deviceInfo = input.deviceInfo,
            )
            .toJSON(),
    )
  }

  private fun buildInput(request: Request): OpaGateInput {
    val clientStatement = request.client.clientStatement()
    val kvnr = request.userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR)

    return OpaGateInput(
        clientId = request.client.id,
        clientPlatform = clientStatement?.platform?.value,
        clientProductID = clientStatement?.posture?.productId,
        clientProductVersion = clientStatement?.posture?.productVersion,
        clientRegistrationTimestamp = request.clientData.lastAccess.toEpochSecond(ZoneOffset.UTC),
        grantType = request.grantType,
        scopes = request.scopes,
        authenticationMethodsReferences = splitSpaceSeparated(request.userSession.getNote(ATTRIBUTE_MOBILEUSER_AMR)),
        authenticationContextClassReference = request.userSession.getNote(ATTRIBUTE_MOBILEUSER_ACR),
        audiences = request.audiences,
        ipAddress = request.session.clientIP,
        previousIpAddress = request.client.attributes[ATTRIBUTE_LAST_CLIENT_IP] ?: "Unknown",
        postureType = clientStatement?.postureType?.value,
        // A_26973-01 id_token user-data mapping: identifier/commonName from »urn:telematik:claims:id«,
        userIdentifier = kvnr,
        // A_26973-01 professionOID from »urn:telematik:claims:profession«.
        userProfessionOid = request.userSession.getNote(ATTRIBUTE_MOBILEUSER_PROFESSION_OID),
        userCommonName = kvnr,
        deviceInfo = clientStatement?.posture?.toOpaDeviceInfo(),
    )
  }

  companion object {
    fun splitSpaceSeparated(value: String?): List<String> = value?.split(' ')?.filter { it.isNotBlank() }.orEmpty()

    /**
     * Two sources only — both are the scopes the client asked for at authorize, not the token-request body:
     * - `requested` — confirmed auth-code (`Issuance.Full`); Keycloak passes the authorize `scope` into
     *   `createTokenResponseBuilder`
     * - client-session note `SCOPE` — email-binding token exchange, when the current token only has the
     *   reduced binding scopes and the original authorize scope must be restored
     */
    fun scopesOf(requested: String?, clientSession: AuthenticatedClientSessionModel?): List<String> {
      val fromRequest = splitSpaceSeparated(requested)
      if (fromRequest.isNotEmpty()) return fromRequest
      return splitSpaceSeparated(clientSession?.getNote(OAuth2Constants.SCOPE))
    }

    /**
     * Audience from the client-session note written during email-binding issuance
     * (`persistRequestedAudience`). Used when exchanging the reduced binding token for a full token:
     * the original `audience` is no longer on the request.
     */
    fun audiencesOf(clientSession: AuthenticatedClientSessionModel): List<String>? =
        parseAudiences(clientSession.getNote(OAuth2Constants.AUDIENCE))

    /**
     * Two sources only:
     * - token-request body `audience` — confirmed auth-code (`Issuance.Full`)
     * - client-session note — email-binding token exchange, after the body param is gone
     */
    fun audiencesOf(formParams: MultivaluedMap<String, String>, clientSession: AuthenticatedClientSessionModel?): List<String>? =
        parseAudiences(formParams.getFirst(OAuth2Constants.AUDIENCE)) ?: clientSession?.let { audiencesOf(it) }

    private fun parseAudiences(raw: String?): List<String>? {
      if (raw.isNullOrBlank()) return null
      return raw.split(',', ' ').map { it.trim() }.filter { it.isNotBlank() }.ifEmpty { null }
    }
  }
}

private fun ClientModel.clientStatement(): ClientStatementData? {
  val raw = getAttribute(ATTRIBUTE_CLIENT_STATEMENT_RAW) ?: return null
  return runCatching { raw.toObject<ClientStatementData>() }
      .onFailure { logger.warnf(it, "Failed to read client statement of client »%s«", clientId) }
      .getOrNull()
}
