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

import de.gematik.zeta.zetaguard.keycloak.commons.JsonUtil.toObject
import de.gematik.zeta.zetaguard.keycloak.commons.opa.OpaSessionContext
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILEUSER_KVNR
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_MOBILE_OPA_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_REQUESTED_SCOPES
import de.gematik.zeta.zetaguard.keycloak.commons.server.ATTRIBUTE_SMCB_CONTEXT
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_ID
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PRODUCT_VERSION
import de.gematik.zeta.zetaguard.keycloak.commons.server.CLAIM_PROFESSION_OID
import de.gematik.zeta.zetaguard.keycloak.commons.server.toScopes
import de.gematik.zeta.zetaguard.keycloak.commons.smcb.ZetaGuardTokenExchangeData
import de.gematik.zeta.zetaguard.keycloak.plugins.opa.OpaGateInput
import org.keycloak.OAuth2Constants
import org.keycloak.models.KeycloakSession
import org.keycloak.models.UserSessionModel
import org.keycloak.representations.RefreshToken

internal sealed interface RefreshOpaReplay {
  data class Smcb(val data: ZetaGuardTokenExchangeData) : RefreshOpaReplay

  data class Mobile(val data: OpaSessionContext) : RefreshOpaReplay
}

internal fun refreshOpaReplay(userSession: UserSessionModel?): RefreshOpaReplay? {
  val smcbContext = userSession?.getNote(ATTRIBUTE_SMCB_CONTEXT)
  val mobileContext = userSession?.getNote(ATTRIBUTE_MOBILE_OPA_CONTEXT)

  return when {
    smcbContext != null -> RefreshOpaReplay.Smcb(smcbContext.toObject())
    mobileContext != null -> RefreshOpaReplay.Mobile(mobileContext.toObject())
    else -> null
  }
}

/**
 * Whether a refresh of a SekIDP session lacks a mobile gate decision of the refreshing client.
 *
 * The access token mapper only issues KVNR claims after that decision, so such a refresh can't succeed: no snapshot
 * (an Allow without TTLs stores none, device code or token-exchange sessions) or the snapshot of another client of
 * the same SSO session. SMC-B sessions and sessions without a KVNR are not affected.
 */
internal fun lacksMobileGateDecision(userSession: UserSessionModel, replay: RefreshOpaReplay?, clientId: String): Boolean =
    when (replay) {
      is RefreshOpaReplay.Smcb -> false
      is RefreshOpaReplay.Mobile -> replay.data.clientId != clientId
      null -> userSession.getNote(ATTRIBUTE_MOBILEUSER_KVNR) != null
    }

internal fun buildRefreshOpaInput(
	session: KeycloakSession,
	refreshToken: RefreshToken,
	replay: RefreshOpaReplay,
	ipAddress: String?,
	previousIpAddress: String?,
): OpaGateInput {
  @Suppress("UNCHECKED_CAST")
  val rawRequestedScopes = session.getAttribute(ATTRIBUTE_REQUESTED_SCOPES, String::class.java)
  val requestedScopes = rawRequestedScopes.toScopes().ifEmpty { null }

  return when (replay) {
    is RefreshOpaReplay.Smcb -> {
      val data = replay.data
      val scopes = requestedScopes ?: data.scopes ?: refreshToken.scope.toScopes()

	    OpaGateInput(
		    grantType = OAuth2Constants.REFRESH_TOKEN,
		    scopes = scopes.toList(),
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
		    userCommonName = data.subjectCommonName,
		    userOrganizationName = data.subjectOrganisation,
		    deviceInfo = data.deviceInfo,
		    attestationTimestamp = data.attestationTimestamp,
	    )
    }

    is RefreshOpaReplay.Mobile -> {
      val data = replay.data
      val scopes = requestedScopes ?: data.scopes ?: refreshToken.scope.toScopes()

	    OpaGateInput(
		    grantType = OAuth2Constants.REFRESH_TOKEN,
		    scopes = scopes.toList(),
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
		    userOrganizationName = data.userOrganizationName,
		    userBirthdate = data.userBirthdate,
		    deviceInfo = data.deviceInfo,
		    attestationTimestamp = data.attestationTimestamp,
	    )
    }
  }
}
